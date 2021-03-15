from flask import (
    Flask,
    request,
    make_response,
    render_template,
    url_for,
    session,
    redirect,
    jsonify,
    send_from_directory,
    current_app,
)
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
import subprocess
import threading
import datetime
import logging
from preprocessing import preprocess_text
import collections
from flask_mail import Mail, Message
from validate_email import validate_email
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
import requests
from PIL import Image
from io import BytesIO
import pytesseract
import re
import os
import time
from flask_weasyprint import HTML, render_pdf
import plotly.graph_objects as go
import plotly
import plotly.io as pio
from nltk.tokenize import sent_tokenize
from collections import OrderedDict
from googlesearch import search
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import atexit
from apscheduler.schedulers.background import BackgroundScheduler
import base64
import torch
from pytorch_transformers import BertTokenizer
from torch.nn.utils.rnn import pad_sequence
from werkzeug.serving import WSGIRequestHandler

app = Flask(__name__)
app.config["SECRET_KEY"] = "MYSECRETKEY"
app.config["MONGO_URI"] = "mongodb://localhost:27017/PlatinumBusinessAnalytics"
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(minutes=30)
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USERNAME"] = "platinum.analytics.business@gmail.com"
app.config["MAIL_PASSWORD"] = "zaryab'sbusiness"
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USE_SSL"] = True

options = Options()
options.headless = True
driver = webdriver.Firefox(executable_path="./geckodriver", options=options)

mongo = PyMongo(app)
mail = Mail(app)
limiter = Limiter(app, key_func=get_remote_address)
scheduler = BackgroundScheduler()

# logging.basicConfig(filename='demo.log', level=logging.DEBUG)

url_serializer = URLSafeTimedSerializer(app.config.get("SECRET_KEY"))


class CustomRequestHandler(WSGIRequestHandler):
    def connection_dropped(self, error, environ=None):
        logging.warning("dropped, but it is called at the end of the execution :(")


def get_model():
    global BERT
    BERT = torch.load("model/bert-model.pickle", map_location=torch.device("cpu"))
    global tokenizer
    tokenizer = BertTokenizer.from_pretrained("bert-large-uncased")
    logging.warning("loaded models successfully!!")


logging.warning("loading models!!!")
get_model()


def get_embeddings(sentences_tokens):
    sentences_embed = []

    for sentence_token in sentences_tokens:
        sentences_embed.append(
            torch.tensor(tokenizer.encode("[CLS]" + " ".join(sentence_token) + "[SEP]"))
        )

    sentences_embed = pad_sequence(sentences_embed, batch_first=True)
    return sentences_embed


def get_result_sentiment(text):
    # logging.warning("TExt Here: "+text)
    sentences_tokens = preprocess_text(text)
    # logging.warning("Sentences: "+str(sentences))
    sentences = get_embeddings(sentences_tokens)
    # logging.warning("Sentences: "+str(sentences))
    with torch.no_grad():
        preds = BERT(sentences)[0]

    pred_classes = list(torch.argmax(preds, axis=1).numpy())

    predict_counter = collections.Counter(pred_classes)
    # logging.warning("This is counter "+str(predict_counter))
    pred_class = predict_counter.most_common(1)[0][0]
    # logging.warning("This is pred_class "+str(pred_class))
    return pred_class


@app.route("/get_sentiment/")
@limiter.exempt
def get_sentiment():
    text = request.args.get("text")
    sentiment = get_result_sentiment(text)
    return jsonify({"Sentiment": str(sentiment)})


def checkAmazonURLExist(url):
    def captcha_solver(self, captcha_url):
        captcha_response = requests.get(captcha_url)
        img = Image.open(BytesIO(captcha_response.content))
        captcha = pytesseract.image_to_string(img)
        logging.log(logging.INFO, str("Captcha Solved: " + captcha))
        return captcha

    driver.get(url)
    while True:
        if (
            driver.find_element_by_xpath("//title").get_attribute("innerText")
            == "Robot Check"
        ):
            logging.log(logging.INFO, "Checking Captcha!")
            link = (
                driver.find_element_by_xpath('//div[@class="a-section"]')
                .find_element_by_xpath(".//img")
                .get_attribute("src")
            )
            solved_captcha = captcha_solver(link)
            logging.log(logging.INFO, "Solved captcha: " + solved_captcha)

            driver.find_element_by_xpath("//input[@class='a-span12']").send_keys(
                solved_captcha
            )
            driver.find_element_by_xpath("//button[@type='submit']").click()

        else:
            body = driver.page_source
            title = (
                driver.find_element_by_xpath("//title")
                .get_attribute("innerText")
                .strip()
            )
            if title == "Page Not Found":
                return False
            else:
                return True


def checkRottenTomatoesURLExist(url):
    r = requests.get(url)
    if r.status_code == 200:
        return True
    else:
        return False


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.route("/")
def home_endpoint():
    return render_template("index.html", session=session)


@app.route("/features/")
def features_endpoint():
    return render_template("features.html", session=session)


@app.route("/demo")
def demo_endpoint():
    return render_template("demo.html", session=session)


@app.route("/projects/")
def projects_endpoint():
    ses = session.keys()
    if "user" not in session.keys():
        return redirect(url_for("login_endpoint"))
    if session["user"] is None:
        return redirect(url_for("login_endpoint"))

    try:
        data = list(
            mongo.db.ProjectData.find(
                {"user_email": session["user"]["user_email"]},
                {
                    "projects.project_name": 1,
                    "_id": 1,
                    "projects._id": 1,
                    "projects.project_category": 1,
                    "projects.date": 1,
                },
            )
        )[0]

        user_id = ObjectId(data["_id"])
        if len(data["projects"]) > 0:
            for project in data["projects"]:
                project["update_count"] = count_updates(
                    user_id, ObjectId(project["_id"])
                )
            data = data["projects"]
        else:
            data = []
        # Here also query the updated_data(seen <= False) count...
        # Query need to be changed...
    except:
        data = []

    return render_template("dashboard.html", session=session, project_list=data)


# Delete this endpoint(Replaced with panel)...
@app.route(
    "/dashboard/project_name=<project_name>/project_category=<project_category>/"
)
def dashboard_endpoint(project_name, project_category):
    if "user" not in session.keys():
        return redirect(url_for("login_endpoint"))
    if session["user"] is None:
        return redirect(url_for("login_endpoint"))

    data = list(
        mongo.db.ProjectData.find(
            {
                "user_email": session["user"]["user_email"],
                "projects": {
                    "$elemMatch": {
                        "project_name": project_name,
                        "project_category": project_category,
                    }
                },
            },
            {
                "_id": 0,
                "projects": {
                    "$elemMatch": {
                        "project_name": project_name,
                        "project_category": project_category,
                    }
                },
            },
        )
    )[0]["projects"][0]["data"]

    if len(data) > 0:
        for review in data:
            if "review_date" in review.keys():
                review["review_date"] = review["review_date"].strftime("%B %d, %Y")
            else:
                review["publish_date"] = review["publish_date"].strftime("%B %d, %Y")

    else:
        data = []

    return render_template(
        "full_dashboard.html",
        session=session,
        reviews_list=data,
        project_name=project_name,
    )


@app.route("/create_project/")
def create_project_endpoint():
    if "user" not in session.keys():
        return redirect(url_for("login_endpoint"))
    if session["user"] is None:
        return redirect(url_for("login_endpoint"))
    if "is_duplicate_project" in session.keys():
        session.pop("is_duplicate_project")
        return render_template(
            "create_project.html",
            session=session,
            is_duplicate=True,
            invalid_reviews_url=False,
            invalid_search_query=False,
        )
    if "invalid_reviews_url" in session.keys():
        session.pop("invalid_reviews_url")
        return render_template(
            "create_project.html",
            session=session,
            is_duplicate=False,
            invalid_reviews_url=True,
            invalid_search_query=False,
        )
    if "invalid_search_query" in session.keys():
        session.pop("invalid_search_query")
        return render_template(
            "create_project.html",
            session=session,
            is_duplicate=False,
            invalid_reviews_url=False,
            invalid_search_query=True,
        )

    return render_template(
        "create_project.html",
        session=session,
        is_duplicate=False,
        invalid_reviews_url=False,
        invalid_search_query=False,
    )


@app.route("/coming_soon/")
def coming_soon_endpoint():
    return render_template("coming_soon.html")


@app.route("/login")
def login_endpoint():
    if "user" in session.keys():
        if session["user"] is None:
            return redirect(url_for("projects_endpoint"))
    if "invalid_cred" in session.keys():
        if session["invalid_cred"] == True:
            session.pop("invalid_cred")
            return render_template(
                "login.html",
                invalid_cred=True,
                reset_link_sent=False,
                is_password_changed=False,
            )
    if "reset_link_sent" in session.keys():
        if session["reset_link_sent"] == True:
            session.pop("reset_link_sent")
            return render_template(
                "login.html",
                invalid_cred=False,
                reset_link_sent=True,
                is_password_changed=False,
            )
    if "is_password_changed" in session.keys():
        if session["is_password_changed"] == True:
            session.pop("is_password_changed")
            return render_template(
                "login.html",
                invalid_cred=False,
                reset_link_sent=False,
                is_password_changed=True,
            )

    return render_template(
        "login.html",
        invalid_cred=False,
        reset_link_sent=False,
        is_password_changed=False,
    )


@app.route("/register/")
def register_endpoint():
    if "user" in session.keys():
        return redirect(url_for("projects_endpoint"))
    if "invalid_provided_email" in session.keys():
        if session["invalid_provided_email"] == True:
            session.pop("invalid_provided_email")
            return render_template(
                "register.html",
                already_account=False,
                invalid_provided_email=True,
                invalid_reg_password=False,
                invalid_reg_repeat_password=False,
            )
    if "already_account" in session.keys():
        if session["already_account"] == True:
            session.pop("already_account")
            return render_template(
                "register.html",
                already_account=True,
                invalid_provided_email=False,
                invalid_reg_password=False,
                invalid_reg_repeat_password=False,
            )
    if "invalid_reg_repeat_password" in session.keys():
        if session["invalid_reg_repeat_password"] == True:
            session.pop("invalid_reg_repeat_password")
            return render_template(
                "register.html",
                already_account=False,
                invalid_provided_email=False,
                invalid_reg_password=False,
                invalid_reg_repeat_password=True,
            )
    if "invalid_reg_password" in session.keys():
        if session["invalid_reg_password"] == True:
            session.pop("invalid_reg_password")
            return render_template(
                "register.html",
                already_account=False,
                invalid_provided_email=False,
                invalid_reg_password=True,
                invalid_reg_repeat_password=False,
            )
    return render_template(
        "register.html",
        already_account=False,
        invalid_provided_email=False,
        invalid_reg_password=False,
        invalid_reg_repeat_password=False,
    )


@app.route("/register/", methods=["POST"])
def register_user():

    try:
        address = request.form.get("email")
        is_valid = validate_email(address, verify=True)
        if not is_valid:
            session["invalid_provided_email"] = True
            return redirect(url_for("register_endpoint"))

        user = mongo.db.ProjectData.find_one({"user_email": request.form.get("email")})
        if not user:

            password = request.form.get("password")
            repeat_password = request.form.get("repassword")

            if password != repeat_password:
                session["invalid_reg_repeat_password"] = True
                return redirect(url_for("register_endpoint"))

            # pwd_reg_result = re.match("^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$", password)
            pwd_reg_result = re.match(
                "^(?=\S{6,20}$)(?=.*?\d)(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])",
                password,
            )

            if not pwd_reg_result:
                session["invalid_reg_password"] = True
                return redirect(url_for("register_endpoint"))

            mongo.db.ProjectData.insert_one(
                {
                    "user_email": request.form.get("email"),
                    "user_password": generate_password_hash(
                        request.form.get("password"), method="sha256"
                    ),
                    "subscribed": True,
                }
            )  # Added subscribed...
            user = mongo.db.ProjectData.find_one(
                {"user_email": request.form.get("email")}
            )
            session["user"] = {
                "user_email": request.form.get("email"),
                "_id": str(user["_id"]).split("'")[0],
            }
            session.permanent = True
            message = Message(
                "Account Created!",
                sender=app.config.get("MAIL_USERNAME"),
                recipients=[address],
            )
            message.html = (
                "<h5>"
                + "Welcome, Your account has been created successfully!"
                + "</h5>"
            )
            try:
                mail.send(message)
            except:
                pass
            return redirect(url_for("home_endpoint"))
        else:
            session["already_account"] = True
            return redirect(url_for("register_endpoint"))

    except:
        return redirect(url_for("register_endpoint"))


@app.route("/login/", methods=["POST"])
def user_login():
    email = request.form.get("email")
    password = request.form.get("password")

    if not email or not password:
        session["invalid_cred"] = True
        return redirect(url_for("login_endpoint"))

    user = mongo.db.ProjectData.find_one({"user_email": email})

    if not user:
        session["invalid_cred"] = True
        return redirect(url_for("login_endpoint"))

    if check_password_hash(user["user_password"], password):
        session["user"] = {
            "user_email": email,
            "_id": str(user["_id"]).split("'")[0],
            "pass": password,
        }
        session.permanent = True

        return redirect(url_for("projects_endpoint"))
        """return make_response("<h1>Login Successful!</h1>", 200,
                             {"auth_token": token})"""
        # return make_response("Login successful!", 200)
    session["invalid_cred"] = True
    return redirect(url_for("login_endpoint"))


@app.route("/create_project/", methods=["POST"])
def create_new_project():

    try:
        project_name = request.form.get("project_name")
        project_category = request.form.get("project_category")

        if project_category == "Product":
            product_url = request.form.get("query")

            #'^https\:\/\/www\.amazon\.com\/?.*\/dp\/[a-zA-Z0-9]*\/?.*$'
            # previous: '^https\:\/\/www\.amazon\.com\/[a-zA-Z0-9_-]*\/dp\/[a-zA-Z0-9]*\/\?.*$'
            if (
                re.match(
                    "^https\:\/\/www\.amazon\.com\/?.*\/dp\/[a-zA-Z0-9]*\/?.*$",
                    product_url,
                )
                is not None
            ):
                if checkAmazonURLExist(product_url) == True:
                    # Here create project and start scraping...
                    results = re.search(
                        "^https\:\/\/www\.amazon\.com\/?.*\/dp\/([a-zA-Z0-9]*)\/?.*$",
                        product_url,
                    )
                    product_id = results.group(1)
                    product_url = (
                        "https://www.amazon.com/2019-Stereo-Headphones-Samsung-Galaxy/product-reviews/"
                        + product_id
                        + "/ref=cm_cr_arp_d_viewopt_srt?ie=UTF8&reviewerType=all_reviews&sortBy=recent&pageNumber=1"
                    )

                    # return make_response('url is valid!')
                else:
                    session["invalid_reviews_url"] = True
                    return redirect(url_for("create_project_endpoint"))
            else:
                session["invalid_reviews_url"] = True
                return redirect(url_for("create_project_endpoint"))

            project_count = mongo.db.ProjectData.find(
                {
                    "user_email": session["user"]["user_email"],
                    "projects": {
                        "$elemMatch": {
                            "project_category": project_category,
                            "project_name": project_name,
                        }
                    },
                }
            ).count()
            if project_count == 0:
                project_id = ObjectId()
                mongo.db.ProjectData.update(
                    {"user_email": session["user"]["user_email"]},
                    {
                        "$push": {
                            "projects": {
                                "_id": project_id,
                                "project_name": project_name,
                                "project_category": project_category,
                                "url": product_url,
                                "date": datetime.date.today().strftime("%b %d, %Y"),
                                "timestamp": datetime.datetime.strptime(
                                    str(datetime.datetime.utcnow().date()), "%Y-%m-%d"
                                ),
                            }
                        }
                    },
                )

                logging.warning(
                    "Before start of amazon scraping id=" + str(id(project_id))
                )

                def scrap_amazon(url, user_id, project_id, timestamp):
                    os.chdir("Amazon")

                    subprocess.check_output(
                        [
                            "scrapy",
                            "crawl",
                            "amazon_reviews",
                            "-a",
                            "url=" + url,
                            "-a",
                            "user_id=" + user_id,
                            "-a",
                            "project_id=" + project_id,
                            "-a",
                            "timestamp=" + timestamp,
                        ]
                    )

                    """subprocess.check_output(['scrapy', 'crawl', 'amazon_reviews', '-a', 'url=' + str(product_url),
                                             '-a', 'user_id=' + str(session["user"]["_id"]),
                                             '-a', 'project_id=' + str(project_id),
                                             '-a', 'timestamp=' + str(None)])"""

                    """subprocess.check_output(['scrapy', 'crawl', 'amazon_reviews', '-a', 'url=' + str(product_url),
                                             '-a', 'user_id=' + str(session["user"]["_id"]),
                                             '-a', 'project_id=' + str(project_id),
                                             '-a', 'timestamp=' + '2020-03-01'])"""
                    os.chdir("..")

                thread_runner = threading.Thread(
                    target=scrap_amazon,
                    args=(
                        str(product_url),
                        str(session["user"]["_id"]),
                        str(project_id),
                        str(None),
                    ),
                )
                thread_runner.start()
                time.sleep(60)
                # scrap_amazon()
                return redirect(
                    url_for(
                        "panel",
                        project_name=project_name,
                        project_category=project_category,
                    )
                )
            else:
                session["is_duplicate_project"] = True
                return redirect(url_for("create_project_endpoint"))

        elif project_category == "Movie":
            # return redirect(url_for('coming_soon_endpoint'))
            product_url = request.form.get("query")
            product_url = product_url + "/reviews?type=user"

            if (
                re.match(
                    "^https\:\/\/www\.rottentomatoes\.com\/m\/[a-zA-Z0-9_]*\/reviews\?type\=user$",
                    product_url,
                )
                is not None
                or re.match(
                    "^https\:\/\/www\.rottentomatoes\.com\/tv\/[a-zA-Z0-9_]*\/s[0-9]*\/reviews\?type\=user$",
                    product_url,
                )
                is not None
            ):
                if (
                    checkRottenTomatoesURLExist(product_url) == True
                ):  # checkRottenTomatoesURLExist validate if link exists or 404..
                    pass
                else:
                    session["invalid_reviews_url"] = True
                    return redirect(url_for("create_project_endpoint"))
            else:
                session["invalid_reviews_url"] = True
                return redirect(url_for("create_project_endpoint"))

            project_count = mongo.db.ProjectData.find(
                {
                    "user_email": session["user"]["user_email"],
                    "projects": {
                        "$elemMatch": {
                            "project_category": project_category,
                            "project_name": project_name,
                        }
                    },
                }
            ).count()
            if project_count == 0:
                project_id = ObjectId()
                mongo.db.ProjectData.update(
                    {"user_email": session["user"]["user_email"]},
                    {
                        "$push": {
                            "projects": {
                                "_id": project_id,
                                "project_name": project_name,
                                "project_category": project_category,
                                "url": product_url,
                                "date": datetime.date.today().strftime("%b %d, %Y"),
                                "timestamp": datetime.datetime.strptime(
                                    str(datetime.datetime.utcnow().date()), "%Y-%m-%d"
                                ),
                            }
                        }
                    },
                )

                logging.warning(
                    "Before start of rotten tomatoes scraping id=" + str(id(project_id))
                )

                def scrap_rotten_tomatoes(product_url, user_id, project_id, timestamp):
                    os.chdir("Rotten_Tomatoes")
                    subprocess.check_output(
                        [
                            "scrapy",
                            "crawl",
                            "rt_reviews",
                            "-a",
                            "url=" + product_url,
                            "-a",
                            "user_id=" + user_id,
                            "-a",
                            "project_id=" + project_id,
                            "-a",
                            "timestamp=" + timestamp,
                        ]
                    )

                    os.chdir("..")

                thread_runner = threading.Thread(
                    target=scrap_rotten_tomatoes,
                    args=(
                        str(product_url),
                        str(session["user"]["_id"]),
                        str(project_id),
                        str(None),
                    ),
                )
                thread_runner.start()
                time.sleep(60)
                # scrap_rotten_tomatoes()
                return redirect(
                    url_for(
                        "panel",
                        project_name=project_name,
                        project_category=project_category,
                    )
                )

        elif project_category == "General":
            # return redirect(url_for('coming_soon_endpoint'))
            product_url = request.form.get("query")

            search_urls = search(product_url)
            valid_query = False
            i = 0
            for url in search_urls:
                if i > 0:
                    valid_query = True
                    break
                i += 1

            if not valid_query:
                session["invalid_search_query"] = True
                return redirect(url_for("create_project_endpoint"))

            project_count = mongo.db.ProjectData.find(
                {
                    "user_email": session["user"]["user_email"],
                    "projects": {
                        "$elemMatch": {
                            "project_category": project_category,
                            "project_name": project_name,
                        }
                    },
                }
            ).count()
            if project_count == 0:
                project_id = ObjectId()
                mongo.db.ProjectData.update(
                    {"user_email": session["user"]["user_email"]},
                    {
                        "$push": {
                            "projects": {
                                "_id": project_id,
                                "project_name": project_name,
                                "project_category": project_category,
                                "url": product_url,
                                "date": datetime.date.today().strftime("%b %d, %Y"),
                                "timestamp": datetime.datetime.strptime(
                                    str(datetime.datetime.utcnow().date()), "%Y-%m-%d"
                                ),
                            }
                        }
                    },
                )

                logging.warning(
                    "Before start of google scraping id=" + str(id(project_id))
                )

                def scrap_google(query, user_id, project_id, timestamp):
                    os.chdir("Google")
                    subprocess.check_output(
                        [
                            "scrapy",
                            "crawl",
                            "google_results",
                            "-a",
                            "query=" + query,
                            "-a",
                            "user_id=" + user_id,
                            "-a",
                            "project_id=" + project_id,
                            "-a",
                            "timestamp=" + timestamp,
                        ]
                    )

                    """from google_results import GoogleResultsSpider
                    crawler = CrawlerProcess(get_project_settings())
                    crawler.crawl(GoogleResultsSpider, query=str(product_url), user_id=str(session["user"]["_id"]),
                                  project_id=str(project_id), timestamp=str(None))"""
                    os.chdir("..")

                thread_runner = threading.Thread(
                    target=scrap_google,
                    args=(
                        str(product_url),
                        str(session["user"]["_id"]),
                        str(project_id),
                        str(None),
                    ),
                )
                thread_runner.start()
                time.sleep(60)
                # scrap_google()
                return redirect(
                    url_for(
                        "panel",
                        project_name=project_name,
                        project_category=project_category,
                    )
                )
        else:
            return redirect(url_for("coming_soon_endpoint"))

    except:
        return redirect(url_for("create_project_endpoint"))


@app.route(
    "/delete_project/project_name=<project_name>/project_category=<project_category>/"
)
def delete_project(project_name, project_category):
    result = mongo.db.ProjectData.update(
        {"user_email": session["user"]["user_email"]},
        {
            "$pull": {
                "projects": {
                    "project_name": project_name,
                    "project_category": project_category,
                }
            }
        },
    )
    if result["nModified"] == 1:
        return redirect(url_for("projects_endpoint"))

    return redirect(url_for("home_endpoint"))


@app.route("/logout/")
def logout_endpoint():
    session.pop("user", None)
    return redirect(url_for("home_endpoint"))


@app.route("/request_reset")
def request_reset_endpoint():
    if "invalid_reset_email" in session.keys():
        if session["invalid_reset_email"] == True:
            session.pop("invalid_reset_email")
            return render_template("forgot_password.html", invalid_reset_email=True)

    return render_template("forgot_password.html", invalid_reset_email=False)


@app.route("/request_password_reset", methods=["POST"])
def request_reset():
    user = mongo.db.ProjectData.find_one({"user_email": request.form.get("email")})
    if not user:
        session["invalid_reset_email"] = True
        return redirect(url_for("request_reset_endpoint"))
    else:
        token = url_serializer.dumps(user["user_email"], salt="thisisemailsalt")
        message = Message(
            "Password Reset",
            sender=app.config.get("MAIL_USERNAME"),
            recipients=[user["user_email"]],
        )
        link = url_for("reset_password_endpoint", token=token, _external=True)
        message.body = "To reset your password, visit the following link " + link
        mail.send(message)
        session["reset_link_sent"] = True
        return redirect(url_for("login_endpoint"))
    # add 'a password reset link has been sent to your email' to login page and redirect to login page...


@app.route("/reset_password/<token>")
def reset_password_endpoint(token):
    # encrypted mail, and token will be received as url parameter first check validity if valid decrypted mail
    # and show in template also set value of u and v...
    try:
        email = url_serializer.loads(token, salt="thisisemailsalt", max_age=3600)
        if "forget_re_password_invalid" in session.keys():
            if session["forget_re_password_invalid"] == True:
                session.pop("forget_re_password_invalid")
                return render_template(
                    "reset_password.html",
                    token=token,
                    reset_email=email,
                    forget_re_password_invalid=True,
                    forget_password_regex_not_match=False,
                )

        if "forget_password_regex_not_match" in session.keys():
            if session["forget_password_regex_not_match"] == True:
                session.pop("forget_password_regex_not_match")
                return render_template(
                    "reset_password.html",
                    token=token,
                    reset_email=email,
                    forget_re_password_invalid=False,
                    forget_password_regex_not_match=True,
                )

        return render_template(
            "reset_password.html",
            token=token,
            reset_email=email,
            forget_re_password_invalid=False,
            forget_password_regex_not_match=False,
        )
    except SignatureExpired:
        return redirect(url_for("link_expired"))


@app.route("/reset_password", methods=["POST"])
def reset_password():

    try:
        token = request.form.get("v")
        password = request.form.get("password")
        repassword = request.form.get("repassword")

        if password != repassword:
            session["forget_re_password_invalid"] = True
            return redirect(url_for("reset_password_endpoint", token=token))

        # pwd_reg_result = re.match("^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$", password)
        pwd_reg_result = re.match(
            "^(?=\S{6,20}$)(?=.*?\d)(?=.*?[a-z])(?=.*?[A-Z])(?=.*?[^A-Za-z\s0-9])",
            password,
        )
        if not pwd_reg_result:
            session["forget_password_regex_not_match"] = True
            return redirect(url_for("reset_password_endpoint", token=token))

        email = url_serializer.loads(token, salt="thisisemailsalt", max_age=3600)
        mongo.db.ProjectData.update(
            {"user_email": email},
            {
                "$set": {
                    "user_password": generate_password_hash(
                        request.form.get("password"), method="sha256"
                    )
                }
            },
        )
        session["is_password_changed"] = True
        return redirect(url_for("login_endpoint"))
    except SignatureExpired:
        return redirect(url_for("link_expired"))


@app.route("/link_expired")
def link_expired():
    return render_template("link_expired.html")


@app.route("/panel")
def panel():
    if "user" not in session.keys():
        return redirect(url_for("login_endpoint"))
    if session["user"] is None:
        return redirect(url_for("login_endpoint"))
    if "project_name" in request.args.keys():
        temp_project_name = request.args["project_name"]
    if "project_category" in request.args.keys():
        temp_project_category = request.args["project_category"]

    # temp_project_name = "Corona Virus"
    # temp_project_category = "General"
    return render_template(
        "panel.html",
        project_name=temp_project_name,
        project_category=temp_project_category,
    )


def getCollectionSize(
    project_name, project_category, sentiment_filter, date_start, date_end
):
    if sentiment_filter == None and date_start == None and date_end == None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {"$sort": {"projects.data.publish_date": -1}},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                        }
                    },
                    {
                        "$group": {
                            "_id": {
                                "user_email": "$user_email",
                                "project_name": "$projects.project_name",
                                "project_category": "$projects.project_category",
                            },
                            "data": {"$push": {"_id": "$projects.data.mention_id"}},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {"$sort": {"projects.data.review_date": -1}},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                        }
                    },
                    {
                        "$group": {
                            "_id": {
                                "user_email": "$user_email",
                                "project_name": "$projects.project_name",
                                "project_category": "$projects.project_category",
                            },
                            "data": {"$push": {"_id": "$projects.data.review_id"}},
                        }
                    },
                ]
            )

    elif sentiment_filter != None and date_start == None and date_end == None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.mention_sentiment": sentiment_filter,
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {"$sort": {"projects.data.publish_date": -1}},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.mention_sentiment": sentiment_filter,
                        }
                    },
                    {
                        "$group": {
                            "_id": {
                                "user_email": "$user_email",
                                "project_name": "$projects.project_name",
                                "project_category": "$projects.project_category",
                            },
                            "data": {"$push": {"_id": "$projects.data.mention_id"}},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_sentiment": sentiment_filter,
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {"$sort": {"projects.data.review_date": -1}},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_sentiment": sentiment_filter,
                        }
                    },
                    {
                        "$group": {
                            "_id": {
                                "user_email": "$user_email",
                                "project_name": "$projects.project_name",
                                "project_category": "$projects.project_category",
                            },
                            "data": {"$push": {"_id": "$projects.data.review_id"}},
                        }
                    },
                ]
            )
    elif sentiment_filter == None and date_start != None and date_end != None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.publish_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.publish_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                        }
                    },
                    {"$sort": {"projects.data.publish_date": -1}},
                    {
                        "$group": {
                            "_id": {
                                "user_email": "$user_email",
                                "project_name": "$projects.project_name",
                                "project_category": "$projects.project_category",
                            },
                            "data": {"$push": {"_id": "$projects.data.mention_id"}},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                        }
                    },
                    {"$sort": {"projects.data.review_date": -1}},
                    {
                        "$group": {
                            "_id": {
                                "user_email": "$user_email",
                                "project_name": "$projects.project_name",
                                "project_category": "$projects.project_category",
                            },
                            "data": {"$push": {"_id": "$projects.data.review_id"}},
                        }
                    },
                ]
            )
    elif sentiment_filter != None and date_start != None and date_end != None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.publish_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                            "projects.data.mention_sentiment": sentiment_filter,
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.publish_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                            "projects.data.mention_sentiment": sentiment_filter,
                        }
                    },
                    {"$sort": {"projects.data.publish_date": -1}},
                    {
                        "$group": {
                            "_id": {
                                "user_email": "$user_email",
                                "project_name": "$projects.project_name",
                                "project_category": "$projects.project_category",
                            },
                            "data": {"$push": {"_id": "$projects.data.mention_id"}},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                            "projects.data.review_sentiment": sentiment_filter,
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                            "projects.data.review_sentiment": sentiment_filter,
                        }
                    },
                    {"$sort": {"projects.data.review_date": -1}},
                    {
                        "$group": {
                            "_id": {
                                "user_email": "$user_email",
                                "project_name": "$projects.project_name",
                                "project_category": "$projects.project_category",
                            },
                            "data": {"$push": {"_id": "$projects.data.review_id"}},
                        }
                    },
                ]
            )
    data = list(data)
    data = data[0]
    data = data["data"]
    return len(data)


def getTimeSeriesData(
    project_name, project_category, sentiment_filter, date_start, date_end
):
    if sentiment_filter == None and date_start == None and date_end == None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                        }
                    },
                    {
                        "$group": {
                            "_id": {"date": "$projects.data.publish_date"},
                            "data": {"$push": "$projects.data.mention_sentiment"},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                        }
                    },
                    {
                        "$group": {
                            "_id": {"date": "$projects.data.review_date"},
                            "data": {"$push": "$projects.data.review_sentiment"},
                        }
                    },
                ]
            )
    elif sentiment_filter != None and date_start == None and date_end == None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.mention_sentiment": sentiment_filter,
                        }
                    },
                    {
                        "$group": {
                            "_id": {"date": "$projects.data.publish_date"},
                            "data": {"$push": "$projects.data.mention_sentiment"},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_sentiment": sentiment_filter,
                        }
                    },
                    {
                        "$group": {
                            "_id": {"date": "$projects.data.review_date"},
                            "data": {"$push": "$projects.data.review_sentiment"},
                        }
                    },
                ]
            )
    elif sentiment_filter == None and date_start != None and date_end != None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.publish_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                        }
                    },
                    {
                        "$group": {
                            "_id": {"date": "$projects.data.publish_date"},
                            "data": {"$push": "$projects.data.mention_sentiment"},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                        }
                    },
                    {
                        "$group": {
                            "_id": {"date": "$projects.data.review_date"},
                            "data": {"$push": "$projects.data.review_sentiment"},
                        }
                    },
                ]
            )
    elif sentiment_filter != None and date_start != None and date_end != None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.publish_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                            "projects.data.mention_sentiment": sentiment_filter,
                        }
                    },
                    {
                        "$group": {
                            "_id": {"date": "$projects.data.publish_date"},
                            "data": {"$push": "$projects.data.mention_sentiment"},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                            "projects.data.review_sentiment": sentiment_filter,
                        }
                    },
                    {
                        "$group": {
                            "_id": {"date": "$projects.data.review_date"},
                            "data": {"$push": "$projects.data.review_sentiment"},
                        }
                    },
                ]
            )

    data1 = list(data)
    data = sorted(data1, key=lambda row: row["_id"]["date"])
    if len(data) > 0:
        date = []
        positive = []
        partially_positive = []
        neutral = []
        partially_negative = []
        negative = []
        for doc in data:
            tdate = doc["_id"]["date"].strftime("%B %d, %Y")
            date.append(tdate)
            if "data" in doc:
                tdata = doc["data"]
                positive.append(tdata.count("4"))
                partially_positive.append(tdata.count("3"))
                neutral.append(tdata.count("2"))
                partially_negative.append(tdata.count("1"))
                negative.append(tdata.count("0"))
            else:
                positive.append(0)
                partially_positive.append(0)
                neutral.append(0)
                partially_negative.append(0)
                negative.append(0)

        time_series_data = {}
        time_series_data["labels"] = date
        if sentiment_filter == None:
            time_series_data["data"] = {
                "positive": positive,
                "partially_positive": partially_positive,
                "neutral": neutral,
                "partially_negative": partially_negative,
                "negative": negative,
            }
        elif sentiment_filter == "0":
            time_series_data["data"] = {"negative": negative}
        elif sentiment_filter == "1":
            time_series_data["data"] = {"partially_negative": partially_negative}
        elif sentiment_filter == "2":
            time_series_data["data"] = {"neutral": neutral}
        elif sentiment_filter == "3":
            time_series_data["data"] = {"partially_positive": partially_positive}
        elif sentiment_filter == "4":
            time_series_data["data"] = {"positive": positive}

        return time_series_data

    pass


def getBarPieData(
    project_name, project_category, sentiment_filter, date_start, date_end
):
    if sentiment_filter == None and date_start == None and date_end == None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.mention_sentiment": {
                                "$in": ["0", "1", "2", "3", "4"]
                            },
                        }
                    },
                    {
                        "$group": {
                            "_id": {"sentiment": "$projects.data.mention_sentiment"},
                            "count": {"$sum": 1},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_sentiment": {
                                "$in": ["0", "1", "2", "3", "4"]
                            },
                        }
                    },
                    {
                        "$group": {
                            "_id": {"sentiment": "$projects.data.review_sentiment"},
                            "count": {"$sum": 1},
                        }
                    },
                ]
            )
    elif sentiment_filter != None and date_start == None and date_end == None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.mention_sentiment": sentiment_filter,
                        }
                    },
                    {
                        "$group": {
                            "_id": {"sentiment": "$projects.data.mention_sentiment"},
                            "count": {"$sum": 1},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_sentiment": sentiment_filter,
                        }
                    },
                    {
                        "$group": {
                            "_id": {"sentiment": "$projects.data.review_sentiment"},
                            "count": {"$sum": 1},
                        }
                    },
                ]
            )
    elif sentiment_filter == None and date_start != None and date_end != None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.publish_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                            "projects.data.mention_sentiment": {
                                "$in": ["0", "1", "2", "3", "4"]
                            },
                        }
                    },
                    {
                        "$group": {
                            "_id": {"sentiment": "$projects.data.mention_sentiment"},
                            "count": {"$sum": 1},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                            "projects.data.review_sentiment": {
                                "$in": ["0", "1", "2", "3", "4"]
                            },
                        }
                    },
                    {
                        "$group": {
                            "_id": {"sentiment": "$projects.data.review_sentiment"},
                            "count": {"$sum": 1},
                        }
                    },
                ]
            )
    elif sentiment_filter != None and date_start != None and date_end != None:
        if project_category == "General":
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.publish_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                            "projects.data.mention_sentiment": sentiment_filter,
                        }
                    },
                    {
                        "$group": {
                            "_id": {"sentiment": "$projects.data.mention_sentiment"},
                            "count": {"$sum": 1},
                        }
                    },
                ]
            )
        else:
            data = mongo.db.ProjectData.aggregate(
                [
                    {
                        "$match": {
                            "user_email": session["user"]["user_email"],
                        }
                    },
                    {"$unwind": "$projects"},
                    {"$unwind": "$projects.data"},
                    {
                        "$match": {
                            "projects.project_name": project_name,
                            "projects.project_category": project_category,
                            "projects.data.review_date": {
                                "$lt": date_end,
                                "$gte": date_start,
                            },
                            "projects.data.review_sentiment": sentiment_filter,
                        }
                    },
                    {
                        "$group": {
                            "_id": {"sentiment": "$projects.data.review_sentiment"},
                            "count": {"$sum": 1},
                        }
                    },
                ]
            )

    data = list(data)
    if len(data) > 0:
        bar_pie_data = {}
        for doc in data:
            if doc["_id"]["sentiment"] == "0":
                bar_pie_data["negative"] = doc["count"]
            elif doc["_id"]["sentiment"] == "1":
                bar_pie_data["partially_negative"] = doc["count"]
            elif doc["_id"]["sentiment"] == "2":
                bar_pie_data["neutral"] = doc["count"]
            elif doc["_id"]["sentiment"] == "3":
                bar_pie_data["partially_positive"] = doc["count"]
            elif doc["_id"]["sentiment"] == "4":
                bar_pie_data["positive"] = doc["count"]

        return bar_pie_data


def get_project_data(
    project_name,
    project_category,
    page_no,
    page_start,
    page_size,
    sentiment_filter,
    date_start,
    date_end,
):
    if project_category == "General":
        if sentiment_filter == None:
            if date_start == None and date_end == None:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "General",
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {"$sort": {"projects.data.publish_date": -1}},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "General",
                            }
                        },
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "mention_category": "$projects.data.mention_category",
                                        "site_url": "$projects.data.site_url",
                                        "publish_date": "$projects.data.publish_date",
                                        "site_title": "$projects.data.site_title",
                                        "mention_sentiment": "$projects.data.mention_sentiment",
                                        "mention_text": "$projects.data.mention_text",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name, "General", None, None, None
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name, "General", None, None, None
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name, "General", None, None, None
                        )

                return jsonify(data)

            else:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "General",
                                "projects.data.publish_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "General",
                                "projects.data.publish_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$sort": {"projects.data.publish_date": -1}},
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "mention_category": "$projects.data.mention_category",
                                        "site_url": "$projects.data.site_url",
                                        "publish_date": "$projects.data.publish_date",
                                        "site_title": "$projects.data.site_title",
                                        "mention_sentiment": "$projects.data.mention_sentiment",
                                        "mention_text": "$projects.data.mention_text",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name, "General", None, date_start, date_end
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name, "General", None, date_start, date_end
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name, "General", None, date_start, date_end
                        )

                return jsonify(data)

        else:

            if date_start == None and date_end == None:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "General",
                                "projects.data.mention_sentiment": sentiment_filter,
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {"$sort": {"projects.data.publish_date": -1}},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "General",
                                "projects.data.mention_sentiment": sentiment_filter,
                            }
                        },
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "mention_category": "$projects.data.mention_category",
                                        "site_url": "$projects.data.site_url",
                                        "publish_date": "$projects.data.publish_date",
                                        "site_title": "$projects.data.site_title",
                                        "mention_sentiment": "$projects.data.mention_sentiment",
                                        "mention_text": "$projects.data.mention_text",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name, "General", sentiment_filter, None, None
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name, "General", sentiment_filter, None, None
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name, "General", sentiment_filter, None, None
                        )

                return jsonify(data)
            else:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "General",
                                "projects.data.mention_sentiment": sentiment_filter,
                                "projects.data.publish_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "General",
                                "projects.data.mention_sentiment": sentiment_filter,
                                "projects.data.publish_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$sort": {"projects.data.publish_date": -1}},
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "mention_category": "$projects.data.mention_category",
                                        "site_url": "$projects.data.site_url",
                                        "publish_date": "$projects.data.publish_date",
                                        "site_title": "$projects.data.site_title",
                                        "mention_sentiment": "$projects.data.mention_sentiment",
                                        "mention_text": "$projects.data.mention_text",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name,
                            "General",
                            sentiment_filter,
                            date_start,
                            date_end,
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name,
                            "General",
                            sentiment_filter,
                            date_start,
                            date_end,
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name,
                            "General",
                            sentiment_filter,
                            date_start,
                            date_end,
                        )

                return jsonify(data)
    elif project_category == "Product":
        if sentiment_filter == None:

            if date_start == None and date_end == None:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "Product",
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {"$sort": {"projects.data.review_date": -1}},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "Product",
                            }
                        },
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "user_picture": "$projects.data.user_picture",
                                        "user_name": "$projects.data.user_name",
                                        "review_date": "$projects.data.review_date",
                                        "review_title": "$projects.data.review_title",
                                        "review_sentiment": "$projects.data.review_sentiment",
                                        "review_data": "$projects.data.review_data",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name, "Product", None, None, None
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name, "Product", None, None, None
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name, "Product", None, None, None
                        )

                return jsonify(data)

            else:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "Product",
                                "projects.data.review_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "Product",
                                "projects.data.review_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$sort": {"projects.data.review_date": -1}},
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "user_picture": "$projects.data.user_picture",
                                        "user_name": "$projects.data.user_name",
                                        "review_date": "$projects.data.review_date",
                                        "review_title": "$projects.data.review_title",
                                        "review_sentiment": "$projects.data.review_sentiment",
                                        "review_data": "$projects.data.review_data",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name, "Product", None, date_start, date_end
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name, "Product", None, date_start, date_end
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name, "Product", None, date_start, date_end
                        )

                return jsonify(data)

        else:

            if date_start == None and date_end == None:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "Product",
                                "projects.data.review_sentiment": sentiment_filter,
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {"$sort": {"projects.data.review_date": -1}},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "Product",
                                "projects.data.review_sentiment": sentiment_filter,
                            }
                        },
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "user_picture": "$projects.data.user_picture",
                                        "user_name": "$projects.data.user_name",
                                        "review_date": "$projects.data.review_date",
                                        "review_title": "$projects.data.review_title",
                                        "review_sentiment": "$projects.data.review_sentiment",
                                        "review_data": "$projects.data.review_data",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name, "Product", sentiment_filter, None, None
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name, "Product", sentiment_filter, None, None
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name, "Product", sentiment_filter, None, None
                        )

                return jsonify(data)
            else:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "Product",
                                "projects.data.review_sentiment": sentiment_filter,
                                "projects.data.review_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "Product",
                                "projects.data.review_sentiment": sentiment_filter,
                                "projects.data.review_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$sort": {"projects.data.review_date": -1}},
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "user_picture": "$projects.data.user_picture",
                                        "user_name": "$projects.data.user_name",
                                        "review_date": "$projects.data.review_date",
                                        "review_title": "$projects.data.review_title",
                                        "review_sentiment": "$projects.data.review_sentiment",
                                        "review_data": "$projects.data.review_data",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name,
                            "Product",
                            sentiment_filter,
                            date_start,
                            date_end,
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name,
                            "Product",
                            sentiment_filter,
                            date_start,
                            date_end,
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name,
                            "Product",
                            sentiment_filter,
                            date_start,
                            date_end,
                        )

                return jsonify(data)
    elif project_category == "Movie":
        if sentiment_filter == None:

            if date_start == None and date_end == None:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "Movie",
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {"$sort": {"projects.data.review_date": -1}},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "Movie",
                            }
                        },
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "user_picture": "$projects.data.user_picture",
                                        "user_name": "$projects.data.user_name",
                                        "review_date": "$projects.data.review_date",
                                        "review_sentiment": "$projects.data.review_sentiment",
                                        "review_data": "$projects.data.review_data",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name, "Movie", None, None, None
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name, "Movie", None, None, None
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name, "Movie", None, None, None
                        )

                return jsonify(data)

            else:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "Movie",
                                "projects.data.review_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "Movie",
                                "projects.data.review_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$sort": {"projects.data.review_date": -1}},
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "user_picture": "$projects.data.user_picture",
                                        "user_name": "$projects.data.user_name",
                                        "review_date": "$projects.data.review_date",
                                        "review_sentiment": "$projects.data.review_sentiment",
                                        "review_data": "$projects.data.review_data",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name, "Movie", None, date_start, date_end
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name, "Movie", None, date_start, date_end
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name, "Movie", None, date_start, date_end
                        )

                return jsonify(data)

        else:

            if date_start == None and date_end == None:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "Movie",
                                "projects.data.review_sentiment": sentiment_filter,
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {"$sort": {"projects.data.review_date": -1}},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "Movie",
                                "projects.data.review_sentiment": sentiment_filter,
                            }
                        },
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "user_picture": "$projects.data.user_picture",
                                        "user_name": "$projects.data.user_name",
                                        "review_date": "$projects.data.review_date",
                                        "review_sentiment": "$projects.data.review_sentiment",
                                        "review_data": "$projects.data.review_data",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name, "Movie", sentiment_filter, None, None
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name, "Movie", sentiment_filter, None, None
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name, "Movie", sentiment_filter, None, None
                        )

                return jsonify(data)
            else:
                data = mongo.db.ProjectData.aggregate(
                    [
                        {
                            "$match": {
                                "user_email": session["user"]["user_email"],
                                "projects.project_name": project_name,
                                "projects.project_category": "Movie",
                                "projects.data.review_sentiment": sentiment_filter,
                                "projects.data.review_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$unwind": "$projects"},
                        {"$unwind": "$projects.data"},
                        {
                            "$match": {
                                "projects.project_name": project_name,
                                "projects.project_category": "Movie",
                                "projects.data.review_sentiment": sentiment_filter,
                                "projects.data.review_date": {
                                    "$lt": date_end,
                                    "$gte": date_start,
                                },
                            }
                        },
                        {"$sort": {"projects.data.review_date": -1}},
                        {
                            "$group": {
                                "_id": {
                                    "user_email": "$user_email",
                                    "project_name": "$projects.project_name",
                                    "project_category": "$projects.project_category",
                                },
                                "data": {
                                    "$push": {
                                        "user_picture": "$projects.data.user_picture",
                                        "user_name": "$projects.data.user_name",
                                        "review_date": "$projects.data.review_date",
                                        "review_sentiment": "$projects.data.review_sentiment",
                                        "review_data": "$projects.data.review_data",
                                    }
                                },
                            }
                        },
                        {
                            "$group": {
                                "_id": "$_id.user_email",
                                "projects": {
                                    "$push": {
                                        "data": {
                                            "data": {
                                                "$slice": [
                                                    "$data",
                                                    page_start,
                                                    page_size,
                                                ]
                                            }
                                        }
                                    }
                                },
                            }
                        },
                    ]
                )
                data = list(data)
                if len(data) > 0:
                    data = data[0]["projects"][0]["data"]
                    if page_no == 1:
                        data["size"] = getCollectionSize(
                            project_name,
                            "Movie",
                            sentiment_filter,
                            date_start,
                            date_end,
                        )
                        data["time_series_data"] = getTimeSeriesData(
                            project_name,
                            "Movie",
                            sentiment_filter,
                            date_start,
                            date_end,
                        )
                        data["bar_pie_data"] = getBarPieData(
                            project_name,
                            "Movie",
                            sentiment_filter,
                            date_start,
                            date_end,
                        )

                return jsonify(data)


@app.route("/get_page/general/<page_no>", methods=["POST"])
def get_page_general(page_no):
    page_size = 21
    page_no = int(page_no)
    """if page_no == 1:
        page_start = (page_no - 1) * page_size
    else:
        page_start = ((page_no - 1) * page_size) - 1"""
    page_start = (page_no - 1) * (page_size - 1)

    project_name = request.form["project_name"]
    sentiment_filter = None
    date_start = None
    date_end = None
    if "sentiment_filter" in request.form.keys():
        sentiment_filter = request.form["sentiment_filter"]
    if "date_start" in request.form.keys():
        date_start = request.form["date_start"]
        date_start = datetime.datetime.strptime(date_start, "%Y-%m-%d")
    if "date_end" in request.form.keys():
        date_end = request.form["date_end"]
        date_end = datetime.datetime.strptime(date_end, "%Y-%m-%d")

    if (
        sentiment_filter is None
        and date_start is None
        and date_end is None
        and page_no == 1
    ):
        try:
            mongo.db.ProjectData.update(
                {
                    "user_email": session["user"]["user_email"],
                    "projects.project_name": project_name,
                    "projects.project_category": "General",
                },
                {"$set": {"projects.$.data.$[].seen": True}},
            )
        except:
            pass
        # Here set seen <= True....

    return get_project_data(
        project_name,
        "General",
        page_no,
        page_start,
        page_size,
        sentiment_filter,
        date_start,
        date_end,
    )

    pass


@app.route("/get_page/product/<page_no>", methods=["POST"])
def get_page_product(page_no):
    page_size = 21
    page_no = int(page_no)
    """if page_no == 1:
        page_start = (page_no - 1) * page_size
    else:
        page_start = ((page_no - 1) * page_size) - 1"""
    page_start = (page_no - 1) * (page_size - 1)

    project_name = request.form["project_name"]
    sentiment_filter = None
    date_start = None
    date_end = None
    if "sentiment_filter" in request.form.keys():
        sentiment_filter = request.form["sentiment_filter"]
    if "date_start" in request.form.keys():
        date_start = request.form["date_start"]
        date_start = datetime.datetime.strptime(date_start, "%Y-%m-%d")
    if "date_end" in request.form.keys():
        date_end = request.form["date_end"]
        date_end = datetime.datetime.strptime(date_end, "%Y-%m-%d")

    if (
        sentiment_filter is None
        and date_start is None
        and date_end is None
        and page_no == 1
    ):
        try:
            mongo.db.ProjectData.update(
                {
                    "user_email": session["user"]["user_email"],
                    "projects.project_name": project_name,
                    "projects.project_category": "Product",
                },
                {"$set": {"projects.$.data.$[].seen": True}},
            )
        except:
            pass
        # Here set seen <= True....

    return get_project_data(
        project_name,
        "Product",
        page_no,
        page_start,
        page_size,
        sentiment_filter,
        date_start,
        date_end,
    )

    pass


@app.route("/get_page/movie/<page_no>", methods=["POST"])
def get_page_movie(page_no):
    page_size = 21
    page_no = int(page_no)
    """if page_no == 1:
        page_start = (page_no - 1) * page_size
    else:
        page_start = ((page_no - 1) * (page_size-1)) - 1"""

    page_start = (page_no - 1) * (page_size - 1)
    logging.warning("page start: " + str(page_start))

    project_name = request.form["project_name"]
    sentiment_filter = None
    date_start = None
    date_end = None
    if "sentiment_filter" in request.form.keys():
        sentiment_filter = request.form["sentiment_filter"]
    if "date_start" in request.form.keys():
        date_start = request.form["date_start"]
        date_start = datetime.datetime.strptime(date_start, "%Y-%m-%d")
    if "date_end" in request.form.keys():
        date_end = request.form["date_end"]
        date_end = datetime.datetime.strptime(date_end, "%Y-%m-%d")

    if (
        sentiment_filter is None
        and date_start is None
        and date_end is None
        and page_no == 1
    ):
        try:
            mongo.db.ProjectData.update(
                {
                    "user_email": session["user"]["user_email"],
                    "projects.project_name": project_name,
                    "projects.project_category": "Movie",
                },
                {"$set": {"projects.$.data.$[].seen": True}},
            )
        except:
            pass
        # Here set seen <= True....

    return get_project_data(
        project_name,
        "Movie",
        page_no,
        page_start,
        page_size,
        sentiment_filter,
        date_start,
        date_end,
    )

    pass


@app.route("/uploads/<resource_id>")
def get_uploads(resource_id):
    return send_from_directory("static/icon/", resource_id)


def renderTimeSeriesGraph(project_name, project_category, time_series_data):
    fig = go.Figure()
    fig.add_trace(
        go.Scatter(
            x=time_series_data["labels"],
            y=time_series_data["data"]["negative"],
            name="Negative",
            line_color="#ff0000",
            opacity=0.8,
        )
    )

    fig.add_trace(
        go.Scatter(
            x=time_series_data["labels"],
            y=time_series_data["data"]["neutral"],
            name="Neutral",
            line_color="#c0c0c0",
            opacity=0.8,
        )
    )

    fig.add_trace(
        go.Scatter(
            x=time_series_data["labels"],
            y=time_series_data["data"]["partially_negative"],
            name="Partially Negative",
            line_color="#c41e3a",
            opacity=0.8,
        )
    )

    fig.add_trace(
        go.Scatter(
            x=time_series_data["labels"],
            y=time_series_data["data"]["partially_positive"],
            name="Partially Positive",
            line_color="#4f7942",
            opacity=0.8,
        )
    )

    fig.add_trace(
        go.Scatter(
            x=time_series_data["labels"],
            y=time_series_data["data"]["positive"],
            name="Positive",
            line_color="#228b22",
            opacity=0.8,
        )
    )

    fig.update_layout(autosize=False, width=850, height=400)
    svg_name = (
        session["user"]["user_email"]
        + project_name
        + project_category
        + "time-series-graph.svg"
    )
    svg_path = "static/graph/" + svg_name
    if "to_delete" not in session.keys():
        session["to_delete"] = []
    session["to_delete"].append(svg_path)

    plotly.io.orca.config.executable = "/home/malang/anaconda3/bin/orca"
    pio.write_image(fig, svg_path)


def renderBarGraph(project_name, project_category, bar_pie_data):
    color_map = {
        "Negative": "#ff0000",
        "Neutral": "#c0c0c0",
        "Partially Negative": "#c41e3a",
        "Partially Positive": "#4f7942",
        "Positive": "#228b22",
    }
    label_map = {
        "negative": "Negative",
        "neutral": "Neutral",
        "partially_negative": "Partially Negative",
        "partially_positive": "Partially Positive",
        "positive": "Positive",
    }
    labels = [label_map[dv] for dv in bar_pie_data]
    values = [bar_pie_data[dv] for dv in bar_pie_data]
    fig = go.Figure(
        data=[
            go.Bar(
                x=labels,
                y=values,
                marker_color=[
                    color_map[label] for label in labels
                ],  # marker color can be a single color value or an iterable
            )
        ]
    )

    fig.update_layout(autosize=False, width=800, height=500)
    svg_name = (
        session["user"]["user_email"]
        + project_name
        + project_category
        + "bar-graph.svg"
    )
    svg_path = "static/graph/" + svg_name
    if "to_delete" not in session.keys():
        session["to_delete"] = []
    session["to_delete"].append(svg_path)

    plotly.io.orca.config.executable = "/home/malang/anaconda3/bin/orca"
    pio.write_image(fig, svg_path)


def renderPieGraph(project_name, project_category, bar_pie_data):
    color_map = {
        "Negative": "#ff0000",
        "Neutral": "#c0c0c0",
        "Partially Negative": "#c41e3a",
        "Partially Positive": "#4f7942",
        "Positive": "#228b22",
    }
    label_map = {
        "negative": "Negative",
        "neutral": "Neutral",
        "partially_negative": "Partially Negative",
        "partially_positive": "Partially Positive",
        "positive": "Positive",
    }
    labels = [label_map[dv] for dv in bar_pie_data]
    values = [bar_pie_data[dv] for dv in bar_pie_data]
    fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=0.3)])
    fig.update_traces(marker=dict(colors=[color_map[label] for label in labels]))

    svg_name = (
        session["user"]["user_email"]
        + project_name
        + project_category
        + "doughnat-graph.svg"
    )
    svg_path = "static/graph/" + svg_name
    if "to_delete" not in session.keys():
        session["to_delete"] = []
    session["to_delete"].append(svg_path)

    plotly.io.orca.config.executable = "/home/malang/anaconda3/bin/orca"
    pio.write_image(fig, svg_path)


@app.route("/flask_weasy_generate_pdf")
def get_flask_weasy_pdf():
    if "user" not in session.keys():
        return redirect(url_for("login_endpoint"))
    if session["user"] is None:
        return redirect(url_for("login_endpoint"))
    date_start = None
    date_end = None
    date_range = "Not Specified"
    if "project_name" in request.args.keys():
        project_name = request.args["project_name"]
    if "project_category" in request.args.keys():
        project_category = request.args["project_category"]
    if "date_start" in request.args.keys():
        date_start = request.args["date_start"]
        date_start = datetime.datetime.strptime(date_start, "%Y-%m-%d")
    if "date_end" in request.args.keys():
        date_end = request.args["date_end"]
        date_end = datetime.datetime.strptime(date_end, "%Y-%m-%d")
        date_range = (
            date_start.strftime("%B %d, %Y") + " - " + date_end.strftime("%B %d, %Y")
        )

    time_series_data = None
    bar_pie_data = None
    selected_mentions = None
    PAGE_SIZE = 4

    time_series_data = getTimeSeriesData(
        project_name, project_category, None, date_start, date_end
    )
    bar_pie_data = getBarPieData(
        project_name, project_category, None, date_start, date_end
    )
    selected_mentions = get_project_data(
        project_name, project_category, 1, 1, PAGE_SIZE, None, date_start, date_end
    ).get_json()
    selected_mentions = selected_mentions["data"]

    if len(selected_mentions) > 0:
        for review in selected_mentions:
            if "review_date" in review.keys():
                review["review_date"] = " ".join(review["review_date"].split(" ")[:4])
                review["review_data"] = review["review_data"][:200] + "[...]"
            else:
                review["publish_date"] = " ".join(review["publish_date"].split(" ")[:4])
                review["mention_text"] = review["mention_text"][:200] + "[...]"

    renderTimeSeriesGraph(project_name, project_category, time_series_data)
    renderBarGraph(project_name, project_category, bar_pie_data)
    renderPieGraph(project_name, project_category, bar_pie_data)

    rendered_template = render_template(
        "report.html",
        project_name=project_name,
        base_url=session["user"]["user_email"] + project_name + project_category,
        reviews_list=selected_mentions,
        date_range=date_range,
    )

    # return rendered_template
    return render_pdf(HTML(string=rendered_template))


@app.after_request
def after_request(response):
    if "to_delete" in session.keys():
        for file in session["to_delete"]:
            logging.warning("file path: " + os.path.join(os.getcwd(), file))
            if os.path.exists(os.path.join(os.getcwd(), file)):
                os.remove(os.path.join(os.getcwd(), file))
    return response


@app.route("/analyze_text", methods=["POST"])
def analyze_text():
    if "text" in request.form.keys():
        text = request.form["text"]

    sentences = sent_tokenize(text)
    sentence_sentiment = OrderedDict()
    for sentence in sentences:
        r = requests.get(
            "http://127.0.0.1:5000/get_sentiment/", params={"text": sentence}
        )
        if r.status_code == 200:
            sentence_sentiment[sentence] = r.json()["Sentiment"]
        else:
            sentence_sentiment[sentence] = "2"

    r = requests.get("http://127.0.0.1:5000/get_sentiment/", params={"text": text})
    if r.status_code == 200:
        sentence_sentiment["last"] = {text: r.json()["Sentiment"]}
    else:
        sentence_sentiment["last"] = {text: "2"}

    return sentence_sentiment


@app.route("/unsubscribe/<encoded_email>")
def unsubscribe(encoded_email):
    decoded_email = base64.b64decode(encoded_email)
    decoded_email = decoded_email.decode()

    if "invalid_password_unsubscribe" in session.keys():
        session.pop("invalid_password_unsubscribe")
        return render_template(
            "unsubscribe_form.html",
            email=decoded_email,
            invalid_password_unsubscribe=True,
        )

    return render_template("unsubscribe_form.html", email=decoded_email)


@app.route("/unsubscribed", methods=["POST"])
def unsubscribed():
    # Here verify password and then update....
    email = request.form.get("email")
    password = request.form.get("password")
    tencoded_email = base64.b64encode(email.encode())

    if not email or not password:
        session["invalid_password_unsubscribe"] = True
        return redirect(url_for("unsubscribe", encoded_email=tencoded_email))

    user = mongo.db.ProjectData.find_one({"user_email": email})

    if not user:
        session["invalid_password_unsubscribe"] = True
        return redirect(url_for("unsubscribe", encoded_email=tencoded_email))

    if check_password_hash(user["user_password"], password):
        mongo.db.ProjectData.update(
            {"user_email": email}, {"$set": {"subscribed": False}}
        )

        return render_template("unsubscribed.html")
    else:
        session["invalid_password_unsubscribe"] = True
        return redirect(url_for("unsubscribe", encoded_email=tencoded_email))


def count_updates(user_id, project_id):
    data = list(
        mongo.db.ProjectData.aggregate(
            [
                {"$match": {"_id": user_id}},
                {"$unwind": "$projects"},
                {"$unwind": "$projects.data"},
                {
                    "$match": {
                        "projects._id": project_id,
                        "projects.data.seen": {"$in": [False]},
                    }
                },
                {
                    "$group": {
                        "_id": {"seen_count": "$projects.data.seen"},
                        "count": {"$sum": 1},
                    }
                },
            ]
        )
    )

    if len(data) > 0:
        return data[0]["count"]
    else:
        return 0


def weekly_update():
    user_project_list = mongo.db.ProjectData.find(
        {},
        {
            "_id": 1,
            "user_email": 1,
            "subscribed": 1,
            "projects._id": 1,
            "projects.project_name": 1,
            "projects.project_category": 1,
            "projects.url": 1,
            "projects.timestamp": 1,
        },
    )

    for user in user_project_list:
        user_id = user["_id"]
        user_email = user["user_email"]
        subscribed = user["subscribed"]
        logging.warning("user_id: " + str(user_id))
        logging.warning("subscribed: " + str(subscribed))

        updated_count = dict()

        for project in user["projects"]:
            project_id = project["_id"]
            project_name = project["project_name"]
            project_category = project["project_category"]
            timestamp = project["timestamp"]
            url = project["url"]
            logging.warning("project_id: " + str(project_id))
            logging.warning("project_category: " + str(project_category))
            logging.warning("timestamp: " + str(timestamp))
            logging.warning("url: " + url)
            d1 = timestamp.date()
            d2 = datetime.datetime.utcnow().date()
            delta = d2 - d1
            days = delta.days
            logging.warning("days: " + str(days))
            if days >= 0:  # Change here days to 7..
                logging.warning(
                    "Here we'll scrape data for every project satisfy days >= 7"
                )
                if project_category == "Product":

                    def scrap_amazon():
                        os.chdir("Amazon")
                        subprocess.check_output(
                            [
                                "scrapy",
                                "crawl",
                                "amazon_reviews",
                                "-a",
                                "url=" + str(url),
                                "-a",
                                "user_id=" + str(user_id),
                                "-a",
                                "project_id=" + str(project_id),
                                "-a",
                                "timestamp=" + str(timestamp.date()),
                            ]
                        )
                        os.chdir("..")

                    scrap_amazon()
                elif project_category == "Movie":
                    logging.warning(
                        "Before start of rotten tomatoes scraping id="
                        + str(id(project_id))
                    )

                    def scrap_rotten_tomatoes():
                        os.chdir("Rotten_Tomatoes")
                        subprocess.check_output(
                            [
                                "scrapy",
                                "crawl",
                                "rt_reviews",
                                "-a",
                                "url=" + str(url),
                                "-a",
                                "user_id=" + str(user_id),
                                "-a",
                                "project_id=" + str(project_id),
                                "-a",
                                "timestamp=" + str(timestamp.date()),
                            ]
                        )
                        os.chdir("..")

                    scrap_rotten_tomatoes()
                elif project_category == "General":

                    def scrap_google():
                        os.chdir("Google")
                        subprocess.check_output(
                            [
                                "scrapy",
                                "crawl",
                                "google_results",
                                "-a",
                                "query=" + str(url),
                                "-a",
                                "user_id=" + str(user_id),
                                "-a",
                                "project_id=" + str(project_id),
                                "-a",
                                "timestamp=" + str(timestamp.date()),
                            ]
                        )
                        os.chdir("..")

                    scrap_google()

                # Count no of new data instances scraped....
                updated_count[project_name] = {
                    "project_category": project_category,
                    "updated_count": count_updates(user_id, project_id),
                }
                # Update timestamp of project here...
                mongo.db.ProjectData.update(
                    {"_id": user_id, "projects._id": project_id},
                    {
                        "$set": {
                            "projects.$.timestamp": datetime.datetime.strptime(
                                str(datetime.datetime.utcnow().date()), "%Y-%m-%d"
                            )
                        }
                    },
                )

        # Send details of projects updated to user via mail...
        if subscribed is True and len(updated_count) > 0:
            with app.app_context():
                message = Message(
                    "Data Updated",
                    sender=app.config.get("MAIL_USERNAME"),
                    recipients=[user_email],
                )
                html = "<h1>" + "New data collected!" + "</h1>"
                temp_html = ""
                for project_name in updated_count.keys():
                    temp_html += (
                        "<h5>Project Name: "
                        + project_name
                        + " Project Category: "
                        + updated_count[project_name]["project_category"]
                        + " New Data: "
                        + str(updated_count[project_name]["updated_count"])
                        + "</h5>"
                    )
                html += temp_html
                # unsubscribe_a = '<a href=' + "http://127.0.0.1/unsubscribe" + '>' + "Unsubscribe" + '</a>'
                current_app.config["SERVER_NAME"] = "127.0.0.1:5000"
                with current_app.test_request_context():
                    unsubscribe_a = (
                        "<a href="
                        + url_for(
                            "unsubscribe",
                            encoded_email=base64.b64encode(
                                user_email.encode(encoding="utf-8")
                            ),
                            _external=True,
                        )
                        + ">"
                        + "Unsubscribe"
                        + "</a>"
                    )
                html += unsubscribe_a
                message.html = html
                try:
                    mail.send(message)
                    logging.warning("Email has been sent!")
                except Exception as e:
                    print(str(type(e)) + ": " + str(e))


@app.route("/weekly_update")
def weekly_updates():
    weekly_update()
    return make_response("No Response!")


if __name__ == "__main__":
    scheduler.add_job(func=weekly_update, trigger="cron", day="*", hour=0, minute=5)
    scheduler.start()
    atexit.register(
        lambda: scheduler.shutdown()
    )  
    # it shutdowns the thread of schedular which is run independantly...
    app.run(debug=True, use_reloader=False, request_handler=CustomRequestHandler)
