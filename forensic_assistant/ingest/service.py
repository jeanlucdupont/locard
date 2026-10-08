"""Provider-qualified SCM service installation fields, not execution evidence."""
NOTE = ('Event ID 7045 records service installation by Service Control Manager; '
        'it does not by itself prove the service successfully started or executed.')


def is_installation(event):
    return (event.get('provider') == 'Service Control Manager'
            and event.get('channel') == 'System' and event.get('event_id') == 7045)


def fields(event):
    from forensic_assistant.database.context import payload
    from .normalize import clean
    data = payload(event)
    return {key: clean(data.get(name)) for key, name in (
        ('service_name', 'ServiceName'), ('image_path', 'ImagePath'),
        ('service_type', 'ServiceType'), ('start_type', 'StartType'), ('account', 'AccountName'))}
