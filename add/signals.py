
def populate_models(sender, **kwargs):
    from django.apps import apps
    from .apps import App1Config
    from django.contrib.auth.models import User
    from django.contrib.auth.models import group
    import logging

    logging.basicConfig(format='[%(asctime)s] %(levelname)s: %(message)s', level=logging.DEBUG)
    logger = logging.getLogger(__name__)

    g1 = Group.objects.create(name='reviewer')
    logger.debug("Created reviewer group")
