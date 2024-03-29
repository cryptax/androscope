# Androscope

Androscope is a Django project to search malware by features they offer/implement.
This is the source code for [Androscope](https://androscope.fortinet-cse.com).

- Documentation: [here](https://cryptax.medium.com/androscope-5ab588ec5b3)

*This project is an open-source beta research project. It is not "official" nor a product. The online instance has been closed due to little community use (apart me).*

# Running the server


## Locally

- Modify `./androscope/settings.py` and set `DEBUG = True`.
- Install requirement in your Python virtual environment, and finally run the server (inside the Python venv):

```
python manage.py runserver
```


## Deploy mode

- Check that `./androscope/settings.py` had `DEBUG = False`
- Set environment variable DJANGO_SECRET_KEY, VIRUSTOTAL_APIKEY and KOODOUS_APIKEY
- `docker-compose build`
- `docker-compose up -d`

## Database

- To create the super user in Django Admin: `python3 manage.py createsuperuser`
- To reset the database, move `db.sqlite3` to another name (backup). Then, re-apply migrations, and create super user.


# Testing

- To test everything: `python3 manage.py test add/`
- To test something specific: `python3 manage.py test add.testviews.ViewsTests.test_post_select`


# Code

- `./add`: Django application. This is where most features are implemented
- `./androscope`: main Django project.
- `./nginx`: I use Nginx as *reverse proxy* to pass incoming requests to Gunicorn. Then I use Gunicorn as *Web Server Gateway Interface* (WSGI) server to run the Python web app, Androscope. You can use something else ;)
