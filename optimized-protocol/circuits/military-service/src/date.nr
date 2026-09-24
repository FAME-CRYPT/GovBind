pub struct Date {
    year: u32,
    month: u32,
    day: u32,
}

fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0) & ((year % 100 != 0) | (year % 400 == 0))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    assert(month >= 1 & month <= 12);

    if month == 2 {
        if is_leap_year(year) {
            29
        } else {
            28
        }
    } else if (month == 4) | (month == 6) | (month == 9) | (month == 11) {
        30
    } else {
        31
    }
}

pub fn from_yyyymmdd(value: u32) -> Date {
    let year = value / 10000;
    let month = (value / 100) % 100;
    let day = value % 100;

    assert(year >= 2000 & year <= 9999);
    assert(month >= 1 & month <= 12);
    assert(day >= 1 & day <= days_in_month(year, month));

    Date { year, month, day }
}

pub fn from_ddmmyyyy_ascii(value: [u8; 10]) -> Date {
    assert(value[2] == 47);
    assert(value[5] == 47);

    let mut digits = [0 as u32; 8];
    let positions = [0, 1, 3, 4, 6, 7, 8, 9];
    for i in 0..8 {
        let byte = value[positions[i]];
        assert(byte >= 48 & byte <= 57);
        digits[i] = (byte - 48) as u32;
    }

    let day = digits[0] * 10 + digits[1];
    let month = digits[2] * 10 + digits[3];
    let year = digits[4] * 1000 + digits[5] * 100 + digits[6] * 10 + digits[7];
    assert(year >= 2000 & year <= 9999);
    assert(month >= 1 & month <= 12);
    assert(day >= 1 & day <= days_in_month(year, month));

    Date { year, month, day }
}

pub fn add_months_clamped(date: Date, months: u32) -> Date {
    assert(months <= 1200);
    let absolute_month = date.year * 12 + (date.month - 1) + months;
    let year = absolute_month / 12;
    let month = absolute_month % 12 + 1;
    let maximum_day = days_in_month(year, month);
    let day = if date.day > maximum_day {
        maximum_day
    } else {
        date.day
    };
    Date { year, month, day }
}

pub fn is_strictly_after(left: Date, right: Date) -> bool {
    (left.year > right.year)
        | ((left.year == right.year) & (left.month > right.month))
        | ((left.year == right.year) & (left.month == right.month) & (left.day > right.day))
}

#[test]
fn leap_year_and_month_clamping() {
    let leap = from_yyyymmdd(20240229);
    assert(is_leap_year(leap.year));

    let january = from_yyyymmdd(20260131);
    let february = add_months_clamped(january, 1);
    assert(february.year == 2026);
    assert(february.month == 2);
    assert(february.day == 28);
}
