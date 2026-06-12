from nautobot.apps.jobs import register_jobs

from .ddi import BIND9JobHookReceiver, BIND9TemplatingJob

register_jobs(BIND9TemplatingJob, BIND9JobHookReceiver)
