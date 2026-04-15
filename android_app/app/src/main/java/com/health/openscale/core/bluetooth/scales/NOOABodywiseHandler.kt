/*
 * openScale
 * Copyright (C) 2025 haakools
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.health.openscale.core.bluetooth.scales

import android.bluetooth.le.ScanResult
import com.health.openscale.core.bluetooth.data.ScaleMeasurement
import com.health.openscale.core.bluetooth.data.ScaleUser
import com.health.openscale.core.bluetooth.libs.StandardImpedanceLib
import com.health.openscale.core.service.ScannedDeviceInfo

/**
 * Handler for the MovingLife / XiangShan (香山 / SenSun) iF-series body-fat scale.
 * Reverse-engineered from MovingLife app com.moving.movinglife v5.12.4.
 *
 * ── Protocol ─────────────────────────────────────────────────────────────────
 * This is a BROADCAST-ONLY scale. No GATT connection is made. All data is sent
 * inside BLE Manufacturer Specific advertising packets (Company ID 0x0100).
 *
 * ── Advertising packet — Manufacturer Specific payload (17 bytes after company ID 0x0100) ──
 *
 *  Byte  0    : 0x01  — broadcast format version
 *  Byte  1    : 0x03  — always 0x03
 *  Byte  2    : 0x16  — always 0x16
 *  Bytes 3-8  : MAC address of scale (6 bytes)
 *  Byte  9    : status flag
 *                 0x01 = stable measurement complete (weight + impedance valid)
 *                 0x21 = live/stepping-on (data not yet stable)
 *  Bytes 10-11: weight, big-endian, unit = 100 g  → divide by 10 for kg
 *                 e.g. 0x0413 = 1043 → 104.3 kg  (confirmed 2026-04-15)
 *  Bytes 12-13: impedance, big-endian, unit = Ω
 *                 e.g. 0x01E0 = 480 Ω             (confirmed 2026-04-15)
 *  Byte  14   : 0x81 when BIA data present (bit 7 set), else 0x01 (weight only)
 *  Byte  15   : unit indicator (0x01 = kg, others TBD)
 *  Byte  16   : checksum = LSB of sum(companyId_low + companyId_high + data[0..15])
 *               Company ID 0x0100 is transmitted little-endian: low=0x00, high=0x01
 *
 * ── Body composition ─────────────────────────────────────────────────────────
 * The proprietary MovingLife algorithm (bodyFatScaleAlg_2.4.14) cannot be
 * replicated. openScale's StandardImpedanceLib is used instead; results will
 * be close but may differ slightly from the MovingLife app.
 */
class NOOABodywiseHandler : ScaleDeviceHandler() {

    companion object {
        private const val COMPANY_ID       = 0x0100
        private const val STATUS_STABLE    = 0x01   // may or may not be used by this scale
        private const val FLAG_BIA_PRESENT = 0x81   // byte 14: BIA measurement complete
        private const val STABLE_COUNT     = 3      // consecutive forwarded readings at same weight
    }

    // ── Per-session stability tracking ──────────────────────────────────────
    // The adapter dedups identical packets so we only see one per ~1-2 s.
    // Track consecutive forwarded readings at the same raw weight; once we reach
    // STABLE_COUNT we consider the reading confirmed regardless of the status byte.
    private var lastWeightRaw: Int = -1
    private var stableCount: Int   = 0

    // ── Device matching ──────────────────────────────────────────────────────

    override fun supportFor(device: ScannedDeviceInfo): DeviceSupport? {
        // XiangShan iF-series scales advertise as "IF_A7", "IF_B3", etc.
        if (!device.name.uppercase().startsWith("IF_")) return null
        return DeviceSupport(
            displayName  = "MovingLife Scale (XiangShan iF-series)",
            capabilities = setOf(DeviceCapability.LIVE_WEIGHT_STREAM, DeviceCapability.BODY_COMPOSITION),
            implemented  = setOf(DeviceCapability.LIVE_WEIGHT_STREAM, DeviceCapability.BODY_COMPOSITION),
            linkMode     = LinkMode.BROADCAST_ONLY
        )
    }

    // ── Broadcast receiving ──────────────────────────────────────────────────

    override fun onAdvertisement(result: ScanResult, user: ScaleUser): BroadcastAction {
        val data = result.scanRecord?.getManufacturerSpecificData(COMPANY_ID)
            ?: return BroadcastAction.IGNORED

        if (data.size < 17) {
            logD("Payload too short (${data.size}b), skipping")
            return BroadcastAction.IGNORED
        }

        if (!isChecksumValid(data)) {
            logD("Bad checksum: ${data.toHexString()}")
            return BroadcastAction.IGNORED
        }

        val status       = data[9].toInt()  and 0xFF
        val flags        = data[14].toInt() and 0xFF
        val unit         = data[15].toInt() and 0xFF
        val weightRaw    = ((data[10].toInt() and 0xFF) shl 8) or (data[11].toInt() and 0xFF)
        val weightKg     = weightRaw / 10.0f
        val impedanceOhm = parseImpedance(data)
        val biaPresent   = flags == FLAG_BIA_PRESENT

        if (weightKg !in 1.0f..300.0f) return BroadcastAction.CONSUMED_KEEP_SCANNING

        // Log every forwarded packet so we can see what actually changes when
        // the scale locks in. This is the data we need to finalise the protocol.
        logI("pkt: status=0x${"%02X".format(status)} flags=0x${"%02X".format(flags)} " +
             "unit=0x${"%02X".format(unit)} weight=${"%.1f".format(weightKg)}kg " +
             "impedance=${impedanceOhm}Ω stableCount=$stableCount/${STABLE_COUNT} " +
             "raw=[${data.toHexString()}]")

        // ── Stability detection ────────────────────────────────────────────────
        // Path 1: scale explicitly signals stability via status byte (0x01) or
        //         BIA-present flag (0x81 in byte 14) — whichever it uses.
        val explicitlyStable = (status == STATUS_STABLE) || biaPresent

        // Path 2: weight hasn't changed over STABLE_COUNT consecutive forwarded
        //         packets (handles scales that never change their status byte).
        if (weightRaw == lastWeightRaw) stableCount++ else { lastWeightRaw = weightRaw; stableCount = 1 }
        val implicitlyStable = stableCount >= STABLE_COUNT

        if (!explicitlyStable && !implicitlyStable) {
            return BroadcastAction.CONSUMED_KEEP_SCANNING
        }

        // ── Publish ────────────────────────────────────────────────────────────
        logI("Stable confirmed (explicit=$explicitlyStable implicit=$implicitlyStable): " +
             "weight=${"%.1f".format(weightKg)}kg  impedance=${impedanceOhm}Ω  biaPresent=$biaPresent")

        val measurement = ScaleMeasurement().apply { weight = weightKg }
        if (biaPresent && impedanceOhm > 0) {
            applyBodyComposition(measurement, weightKg, impedanceOhm, user)
        } else if (impedanceOhm > 0) {
            // Impedance is present but flag hasn't been set — still apply BIA.
            // Remove this branch once we know the exact flag behaviour.
            logI("impedance present but biaPresent=false — applying BIA anyway")
            applyBodyComposition(measurement, weightKg, impedanceOhm, user)
        }
        publish(measurement)
        return BroadcastAction.CONSUMED_STOP
    }

    // ── Parsing ──────────────────────────────────────────────────────────────

    /** Bytes 12-13, big-endian, unit = Ω. Confirmed: 0x01E0 = 480 Ω. */
    private fun parseImpedance(data: ByteArray): Int =
        ((data[12].toInt() and 0xFF) shl 8) or (data[13].toInt() and 0xFF)

    override fun onDisconnected() {
        lastWeightRaw = -1
        stableCount   = 0
    }

    // ── Body composition ─────────────────────────────────────────────────────

    private fun applyBodyComposition(
        measurement: ScaleMeasurement,
        weightKg: Float,
        impedanceOhm: Int,
        user: ScaleUser
    ) {
        try {
            val lib = StandardImpedanceLib(
                gender    = user.gender,
                age       = user.age,
                weightKg  = weightKg.toDouble(),
                heightM   = user.bodyHeight / 100.0,
                impedance = impedanceOhm.toDouble()
            )
            measurement.fat       = lib.totalFatPercentage.toFloat()
            measurement.water     = lib.totalBodyWaterPercentage.toFloat()
            measurement.muscle    = lib.skeletalMusclePercentage.toFloat()
            measurement.bone      = lib.boneMassKg.toFloat()
            measurement.lbm       = lib.fatFreeMassKg.toFloat()
            measurement.bmr       = lib.basalMetabolicRate.toFloat()
            measurement.impedance = impedanceOhm.toDouble()
        } catch (e: Exception) {
            logW("Body composition calculation failed: ${e.message}")
        }
    }

    // ── Checksum ─────────────────────────────────────────────────────────────

    /**
     * Checksum = LSB of sum(companyId_low + companyId_high + data[0..15]).
     * Company ID 0x0100 is on-wire little-endian: low byte = 0x00, high byte = 0x01.
     * Verified against all captured packets (2026-04-15).
     */
    private fun isChecksumValid(data: ByteArray): Boolean {
        if (data.size < 17) return false
        var sum = 0x00 + 0x01  // low byte then high byte of Company ID 0x0100
        for (i in 0 until 16) sum += data[i].toInt() and 0xFF
        return (sum and 0xFF) == (data[16].toInt() and 0xFF)
    }

    // ── Utility ──────────────────────────────────────────────────────────────

    private fun ByteArray.toHexString() = joinToString(" ") { "%02X".format(it) }
}
