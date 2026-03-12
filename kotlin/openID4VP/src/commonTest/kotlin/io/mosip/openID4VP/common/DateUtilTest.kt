package io.mosip.openID4VP.common

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DateUtilTest {

    @Test
    fun `formattedCurrentDateTime should return non-null value`() {
        val result = DateUtil.formattedCurrentDateTime()

        assertNotNull(result)
    }

    @Test
    fun `formattedCurrentDateTime should match yyyy-MM-ddTHH-mm-ssZ format`() {
        val result = DateUtil.formattedCurrentDateTime()
        val regex = Regex("""^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$""")

        assertTrue(regex.matches(result))
    }

    @Test
    fun `formattedCurrentDateTime should return different values on consecutive calls`() {
        val first = DateUtil.formattedCurrentDateTime()
        Thread.sleep(1100)
        val second = DateUtil.formattedCurrentDateTime()

        assertTrue(first != second)
    }

    @Test
    fun `formattedCurrentDateTime should return a valid year`() {
        val result = DateUtil.formattedCurrentDateTime()
        val year = result.substring(0, 4).toInt()

        assertTrue(year >= 2024)
    }

    @Test
    fun `formattedCurrentDateTime should return a valid month between 01 and 12`() {
        val result = DateUtil.formattedCurrentDateTime()
        val month = result.substring(5, 7).toInt()

        assertTrue(month in 1..12)
    }

    @Test
    fun `formattedCurrentDateTime should return a valid day between 01 and 31`() {
        val result = DateUtil.formattedCurrentDateTime()
        val day = result.substring(8, 10).toInt()

        assertTrue(day in 1..31)
    }

    @Test
    fun `formattedCurrentDateTime should return valid hours between 00 and 23`() {
        val result = DateUtil.formattedCurrentDateTime()
        val hours = result.substring(11, 13).toInt()

        assertTrue(hours in 0..23)
    }

    @Test
    fun `formattedCurrentDateTime should return valid minutes between 00 and 59`() {
        val result = DateUtil.formattedCurrentDateTime()
        val minutes = result.substring(14, 16).toInt()

        assertTrue(minutes in 0..59)
    }

    @Test
    fun `formattedCurrentDateTime should return valid seconds between 00 and 59`() {
        val result = DateUtil.formattedCurrentDateTime()
        val seconds = result.substring(17, 19).toInt()

        assertTrue(seconds in 0..59)
    }

    @Test
    fun `formattedCurrentDateTime should end with Z`() {
        val result = DateUtil.formattedCurrentDateTime()

        assertTrue(result.endsWith("Z"))
    }
}

