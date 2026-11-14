from django.apps import AppConfig
from django.core.checks import Error, register
from django.utils.translation import gettext_lazy as _


@register("security", "deployment")
def plugin_signing_key_check(app_configs, **kwargs):
    from django.core.exceptions import ValidationError

    from api.plugin_signing_policy import check_plugin_signing_key_policy

    errors = []
    try:
        check_plugin_signing_key_policy()
    except ValidationError as exc:
        errors.append(Error(str(exc), id="api.E014_PLUGIN_SIGNING_KEY_INVALID"))
    return errors


class ApiConfig(AppConfig):
    name = "api"
    verbose_name = _("Camellia 管理")

    def ready(self):
        from api.signals import connect_api_signals

        connect_api_signals()

