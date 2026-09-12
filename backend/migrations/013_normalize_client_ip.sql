-- Node writes an IPv4 client on a dual-stack socket as ::ffff:91.122.9.47.
-- Same address, longer spelling; rewrite the history so the Proxy view is
-- consistent with what the gate records from now on.
UPDATE proxy_events
   SET client_ip = substring(client_ip from 8)
 WHERE client_ip LIKE '::ffff:%.%.%.%';

UPDATE gate_denials
   SET client_ip = substring(client_ip from 8)
 WHERE client_ip LIKE '::ffff:%.%.%.%';
