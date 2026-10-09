CREATE TABLE identity.mail_admission (
  period text NOT NULL CHECK(period IN ('day','hour')),
  window_started bigint NOT NULL,
  attempts integer NOT NULL CHECK(attempts > 0),
  PRIMARY KEY(period,window_started)
);
