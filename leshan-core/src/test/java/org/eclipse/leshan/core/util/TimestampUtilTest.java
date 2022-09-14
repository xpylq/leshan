package org.eclipse.leshan.core.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.Test;

public class TimestampUtilTest {

    @Test
    public void test_instant_to_big_decimal_conversion() {
        List<Instant> inputList = Arrays.asList(null, Instant.EPOCH, Instant.MIN, Instant.MAX,
                Instant.ofEpochSecond(1664832119, 123456789));

        List<BigDecimal> expectedOutputList = Arrays.asList(null, BigDecimal.ZERO,
                BigDecimal.valueOf(-31557014167219200L), new BigDecimal("31556889864403199.999999999"),
                new BigDecimal("1664832119.123456789"));

        List<BigDecimal> outputList = inputList.stream().map(TimestampUtil::fromInstant).collect(Collectors.toList());

        assertEquals(expectedOutputList, outputList);
    }

    @Test
    public void test_big_decimal_to_instant_conversion() {
        List<BigDecimal> inputList = Arrays.asList(null, BigDecimal.ZERO, BigDecimal.valueOf(-31557014167219200L),
                new BigDecimal("31556889864403199.999999999"), new BigDecimal("1664832119.123456789"));

        List<Instant> expectedOutputList = Arrays.asList(null, Instant.EPOCH, Instant.MIN, Instant.MAX,
                Instant.ofEpochSecond(1664832119, 123456789));

        List<Instant> outputList = inputList.stream().map(TimestampUtil::fromSeconds).collect(Collectors.toList());

        assertEquals(expectedOutputList, outputList);
    }

    @Test
    public void test_too_precise_big_decimal_to_instant_conversion() {
        BigDecimal tooPreciseValue = new BigDecimal("1664832119.112233445566");

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> TimestampUtil.fromSeconds(tooPreciseValue));
        assertEquals(
                String.format("Provided timestamp value: %s is too precise - maximum allowed precision is nanoseconds",
                        tooPreciseValue),
                exception.getMessage());
    }

    @Test
    public void test_big_decimal_to_instant_conversion_overflow() {
        BigDecimal invalidValue = BigDecimal.valueOf(Double.MAX_VALUE).add(BigDecimal.valueOf(1));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> TimestampUtil.fromSeconds(invalidValue));
        assertEquals(String.format("Provided timestamp value: %s is too large or too small to be converted to Double",
                invalidValue), exception.getMessage());
    }

    @Test
    public void test_out_of_bounds_big_decimal_to_instant_conversion() {
        List<BigDecimal> invalidValues = Arrays.asList(
                BigDecimal.valueOf(Instant.MAX.getEpochSecond()).add(BigDecimal.valueOf(2)),
                BigDecimal.valueOf(Instant.MIN.getEpochSecond()).subtract(BigDecimal.valueOf(2)));

        invalidValues.forEach(invalidValue -> {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> TimestampUtil.fromSeconds(invalidValue));
            assertEquals(
                    String.format("Provided timestamp value: %s is too large or too small to be converted to Instant",
                            invalidValue),
                    exception.getMessage());
        });
    }
}
