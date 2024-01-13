import requests
from bs4 import BeautifulSoup
import concurrent.futures
import json


# URL = 'https://smartraveller.gov.au/destinations'

def process_row(row):
    link = row.get('link')
    detailed_url = 'https://travel.gc.ca/destinations/' + link
    request = requests.get(detailed_url)

    text = request.text
    parsed_security = BeautifulSoup(text, 'html.parser')
    security_content = parsed_security.find(id='security')
    row['security_content'] = str(security_content)
    return row


def get_dynamic_data():
    URL = 'https://travel.gc.ca/travelling/advisories'
    print('DEBUG: start')
    htpp_requst = requests.get(URL, timeout=5)
    html = htpp_requst.text
    parsed_html = BeautifulSoup(html, 'html.parser')

    table = parsed_html.find(id='reportlist')
    table_body = table.find('tbody')
    rows = table_body.find_all('tr')

    data = []
    for row in rows:
        country_name = row.find('a').text.strip()
        # country_name = country_name.replace('', '\'')
        display, link = display_and_link_name(country_name)
        try:
            risk_content_div = row.find('div', class_=lambda value: value and ('do-not-travel' in value.lower() or
                                                                               'normal-precautions' in value.lower() or
                                                                               'increased-caution' in value.lower() or
                                                                               'reconsider-travel' in value.lower()))
            risk_content = risk_content_div.text.strip() if risk_content_div else None
        except AttributeError:
            risk_content = None
            print(f'No risk content found for {country_name}')
        last_updated = row.find('td', style='width: 200px;').text.strip()
        try:
            svg_img = row.find('img', {'src': True})['src']
        except TypeError:
            svg_img = None
            print(f'No image found for {country_name}')
        if risk_content is None or svg_img is None:
            print(row)
            break

        data.append({
            'risk_image': svg_img,
            'country': display,
            'link': link,
            'risk_content': risk_content,
            'last_updated': last_updated
        })

    final_result = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = [executor.submit(process_row, row) for row in data]

        for f in concurrent.futures.as_completed(results):
            final_result.append(f.result())

    # for result in final_result:
    #     print(result)
    #     print('----------------------------------')

    file = open('../static/data.txt', 'w')
    file.write(json.dumps(final_result, indent=4))
    print('DEBUG: tmm')


def display_and_link_name(country):
    display_name = country

    link_name = country.lower().replace('\u00f4', 'o').replace('\u00e7', 'ç').replace('\u00e9', 'e').replace('\u00fc',
                                                                                                             'u')
    link_name = link_name.replace(' ', '-').replace('(', '').replace(')', '').replace(' &', '')
    link_name = link_name.replace('democratic republic of ', '').replace('republic of ', '')

    return display_name, link_name


get_dynamic_data()
