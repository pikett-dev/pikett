-- The first incident memory key only knew alarm, service and host, so two services of one alarm (HighErrorRate has
-- "service.name", ContainerGone has "app", DiskAlmostFull has "mountpoint") shared one key. It is now built from all
-- identifying labels (app/incidents/memory.py). Keys of earlier incidents are dropped: none of them has a rated
-- analysis yet (ratings came later), so nothing is lost.
UPDATE incident SET memory_key = NULL WHERE memory_key IS NOT NULL;

-- The feedback question under an analysis is a recorded step, retried by the tick like the other messages.
ALTER TABLE incident_analysis ADD COLUMN IF NOT EXISTS feedback_asked_at TIMESTAMPTZ;
