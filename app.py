# import libraries
import numpy as np
import pandas as pd
from keras.utils import pad_sequences,plot_model
from string import printable
from keras.models import Model,load_model
import requests
from urllib.parse import urlparse, urlencode
import ipaddress
import re
import urllib
import urllib.request, urllib.parse, urllib.error
from flask import Flask, request, jsonify, render_template
import pickle
import lightgbm as lgb
from flask import Flask, request, render_template
from feature_extraction import feature_extraction, output_gru

# Define your Flask app
app = Flask(__name__)

# load pre-trained GRU model
gru_model = load_model('GRU.h5')

# Load the pre-trained LightGBM model
lgb_model = pickle.load(open('LightGBM.pkl','rb'))

def check_url_accessibility(url):
    try:
        response = requests.get(url,timeout=(3,10))
        # Check if the status code is in the 200 range to ensure successful access.
        if 200 <= response.status_code < 300:
            return True
        else:
            return False

    except requests.exceptions.RequestException as e:
        return False
    

# Default page of your web app
@app.route("/")
def load():
    return render_template('index.html')

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if request.method == 'POST':
        url = request.form['url']
        if check_url_accessibility(url)!=True:
            return render_template('index.html', prediction_result="This is a Phishing Website")
        if check_url_accessibility(url):
            features = feature_extraction(url)
            lgb_prediction = lgb_model.predict([features])
            prediction_result = lgb_prediction[0]
        else:
            gru_pred = output_gru(url)
            prediction_result = gru_pred
        if prediction_result == 0:
            return render_template('index.html', prediction_result="This is a Phishing Website")
        if prediction_result == 1:
            return render_template('index.html', prediction_result="This is a Legitimate Website")

    return render_template('index.html', prediction_result=prediction_result)

if __name__ == "__main__":
    app.run(debug=True)






