SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";

CREATE TABLE eth (
  packet_id int(11) NOT NULL,
  dst varchar(17) NOT NULL,
  src varchar(17) NOT NULL,
  `type` int(11) NOT NULL,
  PRIMARY KEY (packet_id)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE ip (
  packet_id int(11) NOT NULL,
  version int(11) NOT NULL,
  hdr_len int(11) NOT NULL,
  tos int(11) NOT NULL,
  len int(11) NOT NULL,
  id varchar(4) NOT NULL,
  rb tinyint(1) NOT NULL,
  df tinyint(1) NOT NULL,
  mf tinyint(1) NOT NULL,
  frag_offset int(11) NOT NULL,
  ttl int(11) NOT NULL,
  proto varchar(2) NOT NULL,
  `checksum` varchar(4) NOT NULL,
  src varchar(15) NOT NULL,
  dst varchar(15) NOT NULL,
  PRIMARY KEY (packet_id)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

CREATE TABLE tcp (
  packet_id int(11) NOT NULL,
  srcport int(11) NOT NULL,
  dstport int(11) NOT NULL,
  seq int(11) NOT NULL,
  ack_seq int(11) NOT NULL,
  hdr_len int(11) NOT NULL,
  urg tinyint(1) NOT NULL,
  ack tinyint(1) NOT NULL,
  push tinyint(1) NOT NULL,
  `reset` tinyint(1) NOT NULL,
  syn tinyint(1) NOT NULL,
  fin tinyint(1) NOT NULL,
  window_size int(11) NOT NULL,
  `checksum` varchar(4) NOT NULL,
  PRIMARY KEY (packet_id)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
