# importing required packages
import numpy as np
import pandas as pd
from sklearn import model_selection
from sklearn.metrics import classification_report,confusion_matrix
import requests
from urllib.parse import urlparse, urlencode
import ipaddress
import re
import urllib
import urllib.request, urllib.parse, urllib.error
from datetime import datetime
import pickle
from string import printable
from keras.models import Model,load_model
from keras.utils import pad_sequences,plot_model


# 1 = legitimate
# 0 = phishing

# 1.Domain of the URL (Domain)
def getDomain(url):
  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
    domain = domain.replace("www.","")
  return domain

# 2.Check for IP address in URL (Have_IP)
def havingIP(url):
  try:
    ipaddress.ip_address(url)
    ip = 0
  except:
    ip = 1
  return ip

# 3.Check the presence of @ in URL (Have_At)
def haveAtSign(url):
  if "@" in url:
    at = 0
  else:
    at = 1
  return at

# 4.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
  if len(url) < 54:
    length = 1
  else:
    length = 0
  return length

# 5.Gives number of '/' in URL (URL_Depth)
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth

# 6.Checking for redirection '//' in the url (Redirection)
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 0
    else:
      return 1
  else:
    return 1

# 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
def httpDomain(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 0
  else:
    return 1

#listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

# 8.Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 0
    else:
        return 1

# 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 0          
    else:
        return 1          

# # 10.Web traffic (Web_Traffic)
# def web_traffic(url):
#   try:
#     #Filling the whitespaces in the URL if any
#     url = urllib.parse.quote(url)
#     rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
#         "REACH")['RANK']
#     rank = int(rank)
#   except TypeError:
#         return 0
#   if rank <100000:
#     return 0
#   else:
#     return 1

# 11.Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainAge(domain_name):
  creation_date = domain_name.creation_date
  expiration_date = domain_name.expiration_date
  if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 0
  if ((expiration_date is None) or (creation_date is None)):
      return 0
  elif ((type(expiration_date) is list) or (type(creation_date) is list)):
      return 0
  else:
    ageofdomain = abs((expiration_date - creation_date).days)
    if ((ageofdomain/30) < 6):
      age = 0
    else:
      age = 1
  return age

# 12.End time of domain: The difference between termination time and current time (Domain_End)
def domainEnd(domain_name):
  expiration_date = domain_name.expiration_date
  if isinstance(expiration_date,str):
    try:
      expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except:
      return 0
  if (expiration_date is None):
      return 0
  elif (type(expiration_date) is list):
      return 0
  else:
    today = datetime.now()
    end = abs((expiration_date - today).days)
    if ((end/30) < 6):
      end = 1
    else:
      end = 0
  return end

# 13.IFrame Redirection (iFrame)
def iframe(response):
  if response == "":
      return 0
  else:
      if re.findall(r"[|]", response.text):
          return 1
      else:
          return 0

# 14.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
  if response == "" :
    return 0
  else:
    if re.findall("", response.text):
      return 0
    else:
      return 1

# 15.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
  if response == "":
    return 0
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 1
    else:
      return 0

# 16.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
  if response == "":
    return 0
  else:
    if len(response.history) <= 2:
      return 1
    else:
      return 0

# 17.GRU
def output_gru(url):
  gru_model=load_model("GRU.h5")
  encoded_url=[[printable.index(x) + 1 for x in url if x in printable]]
  max_len=75
  preprocessed_url = pad_sequences(encoded_url, maxlen=max_len, truncating='post')
  return np.argmax(gru_model.predict(preprocessed_url,batch_size=1))


# Function to extract features
def feature_extraction(url):

  features = []

  # Address bar based features (10)
  # features.append(getDomain(url))
  features.append(havingIP(url))
  features.append(haveAtSign(url))
  features.append(getLength(url))
  features.append(getDepth(url))
  features.append(redirection(url))
  features.append(httpDomain(url))
  features.append(tinyURL(url))
  features.append(prefixSuffix(url))

  # HTML & Javascript based features (4)
  try:
    response = requests.get(url)
  except:
    response = ""
  features.append(iframe(response))
  features.append(mouseOver(response))
  features.append(rightClick(response))
  features.append(forwarding(response))
  try:
    response = requests.get(url)
  except requests.exceptions.RequestException as e:
    print("HTTP request error:", e)
    response = None  # Handle the absence of HTTP response
  
  # GRU features
  features.append(output_gru(url))

  return features
