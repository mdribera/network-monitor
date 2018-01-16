USE network_monitor;
DROP TABLE IF EXISTS nm_device_events;

CREATE TABLE nm_device_events (
  id INT NOT NULL auto_increment PRIMARY KEY,
  mac VARCHAR(17) NOT NULL,
  vendor VARCHAR(64),
  ip VARCHAR(15) NOT NULL,
  connected_at timestamp DEFAULT 0,
  last_seen_at timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
