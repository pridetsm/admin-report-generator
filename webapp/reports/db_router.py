"""Routes the long-term metric archive to its own database (`prometheus_snapshot_db`,
Django alias "metrics"), separate from the app's main `admin_report` database -- see
PROMETHEUS-RETENTION-PLAN.md. Independent backup/prune lifecycle, workload isolation from the
app's own transactional data (users, reports, alerts), and easier to relocate to another
volume later if it grows, without untangling it out of the shared app database.

MetricSample has no FK to anything (deliberately -- see its own docstring), so there is no
cross-database relation to worry about; ARCHIVE_MODELS is the only thing this router needs to
know.
"""
ARCHIVE_MODELS = {"metricsample"}


class MetricsRouter:
    def db_for_read(self, model, **hints):
        if model._meta.model_name in ARCHIVE_MODELS:
            return "metrics"
        return None

    def db_for_write(self, model, **hints):
        if model._meta.model_name in ARCHIVE_MODELS:
            return "metrics"
        return None

    def allow_relation(self, obj1, obj2, **hints):
        return None

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        # An archive model belongs ONLY on "metrics"; nothing else belongs on "metrics" at all.
        if model_name in ARCHIVE_MODELS:
            return db == "metrics"
        if db == "metrics":
            return False
        return None
