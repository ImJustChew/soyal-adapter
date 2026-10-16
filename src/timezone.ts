export interface ControllerWallClockFields {
  year: number;
  month: number;
  day: number;
  hour: number;
  minute: number;
  second: number;
}

/** Convert controller wall-clock fields into an instant in the configured zone. */
export function controllerWallClockToDate(fields: ControllerWallClockFields, timeZone?: string): Date {
  validateWallClock(fields);
  const timeZoneName = timeZone?.trim();
  if (!timeZoneName || timeZoneName.toLowerCase() === "local") {
    return new Date(fields.year, fields.month - 1, fields.day, fields.hour, fields.minute, fields.second);
  }

  // The controller stores no offset. Interpret its fields as wall-clock time
  // in the IANA zone, independent of the process timezone (prod is UTC).
  const utcGuess = Date.UTC(fields.year, fields.month - 1, fields.day, fields.hour, fields.minute, fields.second);
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: timeZoneName,
    hour12: false,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(new Date(utcGuess));
  const values = new Map(parts.map((part) => [part.type, Number(part.value)]));
  const zoneAsUtc = Date.UTC(
    values.get("year") ?? fields.year,
    (values.get("month") ?? fields.month) - 1,
    values.get("day") ?? fields.day,
    values.get("hour") ?? fields.hour,
    values.get("minute") ?? fields.minute,
    values.get("second") ?? fields.second,
  );
  return new Date(utcGuess - (zoneAsUtc - utcGuess));
}

/** Extract the controller wall-clock fields for a sanctioned 23H write. */
export function controllerWallClockFields(value: Date, timeZone?: string): ControllerWallClockFields {
  if (Number.isNaN(value.getTime())) throw new Error("controller clock time must be valid");
  const timeZoneName = timeZone?.trim();
  if (!timeZoneName || timeZoneName.toLowerCase() === "local") {
    return {
      year: value.getFullYear(),
      month: value.getMonth() + 1,
      day: value.getDate(),
      hour: value.getHours(),
      minute: value.getMinutes(),
      second: value.getSeconds(),
    };
  }
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: timeZoneName,
    hour12: false,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).formatToParts(value);
  const values = new Map(parts.map((part) => [part.type, Number(part.value)]));
  return {
    year: values.get("year") ?? value.getFullYear(),
    month: values.get("month") ?? value.getMonth() + 1,
    day: values.get("day") ?? value.getDate(),
    hour: values.get("hour") ?? value.getHours(),
    minute: values.get("minute") ?? value.getMinutes(),
    second: values.get("second") ?? value.getSeconds(),
  };
}

function validateWallClock(fields: ControllerWallClockFields): void {
  const value = new Date(Date.UTC(fields.year, fields.month - 1, fields.day, fields.hour, fields.minute, fields.second));
  if (Number.isNaN(value.getTime())
    || value.getUTCFullYear() !== fields.year
    || value.getUTCMonth() !== fields.month - 1
    || value.getUTCDate() !== fields.day
    || value.getUTCHours() !== fields.hour
    || value.getUTCMinutes() !== fields.minute
    || value.getUTCSeconds() !== fields.second) {
    throw new Error("24H clock response contains an invalid calendar date");
  }
}
