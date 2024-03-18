package io.openbas.collectors.sentinel.utils;

import io.openbas.database.model.InjectExpectation;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.time.temporal.ChronoUnit;
import java.util.Locale;

import static java.time.ZoneOffset.UTC;

public class Utils {

  public static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'z'", Locale.FRANCE);

  public static Instant toInstant(final String date) {
    DateTimeFormatter dateTimeFormatter = new DateTimeFormatterBuilder()
        .appendPattern("yyyy-MM-dd'T'HH:mm:ss")
        .optionalStart()
        .appendFraction(ChronoField.NANO_OF_SECOND, 0, 9, true)
        .optionalEnd()
        .appendPattern("'Z'")
        .toFormatter();
    LocalDateTime localDateTime = LocalDateTime.parse(date, dateTimeFormatter);
    ZonedDateTime zonedDateTime = localDateTime.atZone(UTC);
    return zonedDateTime.toInstant();
  }

  public static boolean isExpired(@NotNull final InjectExpectation expectation) {
    return expectation.getCreatedAt().isBefore(Instant.now().minus(15L, ChronoUnit.MINUTES));
  }

}
