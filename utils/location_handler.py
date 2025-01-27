import requests
import logging
from flask import current_app, request


logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def get_country_choices():
    try:
        response = requests.get('https://restcountries.com/v3.1/all?fields=name', timeout=10)
        response.raise_for_status()
        
        countries = response.json()
        if isinstance(countries, list):  # Ensure the response is a list
            choices = sorted([
                (country['name']['common'], country['name']['common'])
                for country in countries if 'name' in country and 'common' in country['name']
            ])
            return choices
        else:
            print("Unexpected data format from API.")
            raise ValueError("Invalid API response format.")
    except requests.exceptions.RequestException as e:
        print(f"Error fetching countries: {e}")
    except (ValueError, KeyError) as e:
        print(f"Error processing country data: {e}")

    # Fallback to a static country list
    fallback_countries = [
        ("United States", "United States"),
        ("Canada", "Canada"),
        ("India", "India")
    ]
    return sorted(fallback_countries)


def get_location(ip_address):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        response.raise_for_status()
        data = response.json()
        return data.get('city', 'Unknown'), data.get('country', 'Unknown')
    except requests.exceptions.RequestException as e:
        print(f"Error fetching location for IP {ip_address}: {e}")
        return None, None
    except KeyError:
        print("Unexpected response structure from IP API.")
        return None, None

