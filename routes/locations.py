"""
Location routes for finding nearby Stanbic Bank services.
Shows ATMs, branches, agents, and mobile money points on Google Maps.
"""

from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
import os
from dotenv import load_dotenv

# Force reload environment variables
load_dotenv(override=True)

locations_bp = Blueprint('locations', __name__, url_prefix='/locations')

# Stanbic Bank Uganda Locations Database
# In production, this would come from a database
STANBIC_LOCATIONS = [
    # Kampala - Main Branches
    {
        'id': 1,
        'name': 'Stanbic Bank - Main Branch (Crown House)',
        'type': 'branch',
        'address': 'Crown House, Kampala Road, Kampala',
        'phone': '+256 312 310 000',
        'services': ['banking', 'atm', 'forex', 'loans'],
        'hours': 'Mon-Fri: 8:30 AM - 5:00 PM, Sat: 8:30 AM - 1:00 PM',
        'lat': 0.3136,
        'lng': 32.5811
    },
    {
        'id': 2,
        'name': 'Stanbic Bank - Garden City',
        'type': 'branch',
        'address': 'Garden City Mall, Kampala',
        'phone': '+256 312 310 100',
        'services': ['banking', 'atm', 'forex'],
        'hours': 'Mon-Sun: 9:00 AM - 8:00 PM',
        'lat': 0.3370,
        'lng': 32.6028
    },
    {
        'id': 3,
        'name': 'Stanbic Bank - Oasis Mall',
        'type': 'branch',
        'address': 'Oasis Mall, Kampala',
        'phone': '+256 312 310 200',
        'services': ['banking', 'atm'],
        'hours': 'Mon-Sun: 10:00 AM - 8:00 PM',
        'lat': 0.3275,
        'lng': 32.5975
    },
    
    # ATMs
    {
        'id': 4,
        'name': 'Stanbic ATM - Acacia Mall',
        'type': 'atm',
        'address': 'Acacia Mall, Kisementi',
        'services': ['withdrawal', 'balance', 'deposit'],
        'hours': '24/7',
        'lat': 0.3342,
        'lng': 32.5978
    },
    {
        'id': 5,
        'name': 'Stanbic ATM - Nakumatt Oasis',
        'type': 'atm',
        'address': 'Nakumatt Oasis, Kampala',
        'services': ['withdrawal', 'balance'],
        'hours': '24/7',
        'lat': 0.3278,
        'lng': 32.5980
    },
    {
        'id': 6,
        'name': 'Stanbic ATM - Entebbe Road',
        'type': 'atm',
        'address': 'Total Entebbe Road',
        'services': ['withdrawal', 'balance', 'deposit'],
        'hours': '24/7',
        'lat': 0.3167,
        'lng': 32.5500
    },
    
    # Bank Agents
    {
        'id': 7,
        'name': 'Stanbic Agent - Wandegeya',
        'type': 'agent',
        'address': 'Wandegeya Market, Kampala',
        'phone': '+256 700 123 456',
        'services': ['deposits', 'withdrawals', 'bill_payments'],
        'hours': 'Mon-Sat: 8:00 AM - 7:00 PM',
        'lat': 0.3304,
        'lng': 32.5681
    },
    {
        'id': 8,
        'name': 'Stanbic Agent - Ntinda',
        'type': 'agent',
        'address': 'Ntinda Trading Centre',
        'phone': '+256 700 234 567',
        'services': ['deposits', 'withdrawals', 'bill_payments'],
        'hours': 'Mon-Sat: 8:00 AM - 7:00 PM',
        'lat': 0.3526,
        'lng': 32.6170
    },
    {
        'id': 9,
        'name': 'Stanbic Agent - Nansana',
        'type': 'agent',
        'address': 'Nansana Town',
        'phone': '+256 700 345 678',
        'services': ['deposits', 'withdrawals'],
        'hours': 'Mon-Sat: 8:00 AM - 6:00 PM',
        'lat': 0.3667,
        'lng': 32.5167
    },
    
    # Mobile Money Points
    {
        'id': 10,
        'name': 'MTN Mobile Money - Kampala Road',
        'type': 'mobile_money',
        'address': 'Kampala Road, Near Post Office',
        'phone': '+256 777 123 456',
        'services': ['mtn_mobile_money', 'deposits', 'withdrawals'],
        'hours': 'Mon-Sun: 7:00 AM - 10:00 PM',
        'lat': 0.3138,
        'lng': 32.5815
    },
    {
        'id': 11,
        'name': 'Airtel Money - William Street',
        'type': 'mobile_money',
        'address': 'William Street, Kampala',
        'phone': '+256 750 234 567',
        'services': ['airtel_money', 'deposits', 'withdrawals'],
        'hours': 'Mon-Sun: 7:00 AM - 10:00 PM',
        'lat': 0.3145,
        'lng': 32.5820
    },
    
    # Additional Locations - Entebbe
    {
        'id': 12,
        'name': 'Stanbic Bank - Entebbe Branch',
        'type': 'branch',
        'address': 'Church Road, Entebbe',
        'phone': '+256 312 310 300',
        'services': ['banking', 'atm', 'forex'],
        'hours': 'Mon-Fri: 8:30 AM - 5:00 PM',
        'lat': 0.0536,
        'lng': 32.4636
    },
    {
        'id': 13,
        'name': 'Stanbic ATM - Entebbe Airport',
        'type': 'atm',
        'address': 'Entebbe International Airport',
        'services': ['withdrawal', 'balance'],
        'hours': '24/7',
        'lat': 0.0423,
        'lng': 32.4435
    },
    
    # Jinja
    {
        'id': 14,
        'name': 'Stanbic Bank - Jinja Branch',
        'type': 'branch',
        'address': 'Main Street, Jinja',
        'phone': '+256 312 310 400',
        'services': ['banking', 'atm', 'forex', 'loans'],
        'hours': 'Mon-Fri: 8:30 AM - 5:00 PM',
        'lat': 0.4244,
        'lng': 33.2042
    },
    
    # Mbarara
    {
        'id': 15,
        'name': 'Stanbic Bank - Mbarara Branch',
        'type': 'branch',
        'address': 'High Street, Mbarara',
        'phone': '+256 312 310 500',
        'services': ['banking', 'atm', 'forex'],
        'hours': 'Mon-Fri: 8:30 AM - 5:00 PM',
        'lat': -0.6092,
        'lng': 30.6619
    }
]


@locations_bp.route('/')
@login_required
def index():
    """Main locations page with map."""
    # Try multiple methods to get the API key
    google_maps_api_key = os.getenv('GOOGLE_MAPS_API_KEY') or os.environ.get('GOOGLE_MAPS_API_KEY', '')
    
    # Debug: Print to console (remove in production)
    print(f"DEBUG: Google Maps API Key loaded: {'Yes' if google_maps_api_key else 'No'}")
    if google_maps_api_key:
        print(f"DEBUG: API Key length: {len(google_maps_api_key)}")
        print(f"DEBUG: API Key (first 10 chars): {google_maps_api_key[:10]}...")
    
    if not google_maps_api_key:
        # Show warning if API key is not set
        return render_template('locations.html', 
                             locations=STANBIC_LOCATIONS,
                             api_key_missing=True)
    
    return render_template('locations.html', 
                         locations=STANBIC_LOCATIONS,
                         google_maps_api_key=google_maps_api_key,
                         api_key_missing=False)


@locations_bp.route('/api/nearby')
@login_required
def get_nearby_locations():
    """Get nearby locations based on user coordinates."""
    try:
        lat = float(request.args.get('lat', 0))
        lng = float(request.args.get('lng', 0))
        radius = float(request.args.get('radius', 10))  # km
        location_type = request.args.get('type', 'all')
        
        # Filter locations by type
        filtered_locations = STANBIC_LOCATIONS
        if location_type != 'all':
            filtered_locations = [loc for loc in STANBIC_LOCATIONS if loc['type'] == location_type]
        
        # Calculate distances (simple approximation)
        import math
        
        def calculate_distance(lat1, lng1, lat2, lng2):
            """Calculate distance between two points in km."""
            R = 6371  # Earth's radius in km
            
            lat1_rad = math.radians(lat1)
            lat2_rad = math.radians(lat2)
            delta_lat = math.radians(lat2 - lat1)
            delta_lng = math.radians(lng2 - lng1)
            
            a = math.sin(delta_lat/2) * math.sin(delta_lat/2) + \
                math.cos(lat1_rad) * math.cos(lat2_rad) * \
                math.sin(delta_lng/2) * math.sin(delta_lng/2)
            
            c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
            distance = R * c
            
            return distance
        
        # Add distance to each location
        nearby_locations = []
        for location in filtered_locations:
            distance = calculate_distance(lat, lng, location['lat'], location['lng'])
            if distance <= radius:
                location_copy = location.copy()
                location_copy['distance'] = round(distance, 2)
                nearby_locations.append(location_copy)
        
        # Sort by distance
        nearby_locations.sort(key=lambda x: x['distance'])
        
        return jsonify({
            'success': True,
            'count': len(nearby_locations),
            'locations': nearby_locations
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500


@locations_bp.route('/api/search')
@login_required
def search_locations():
    """Search locations by name or address."""
    query = request.args.get('q', '').lower()
    location_type = request.args.get('type', 'all')
    
    if not query:
        return jsonify({
            'success': False,
            'message': 'Search query required'
        }), 400
    
    # Filter by type
    filtered_locations = STANBIC_LOCATIONS
    if location_type != 'all':
        filtered_locations = [loc for loc in STANBIC_LOCATIONS if loc['type'] == location_type]
    
    # Search in name and address
    results = [
        loc for loc in filtered_locations
        if query in loc['name'].lower() or query in loc['address'].lower()
    ]
    
    return jsonify({
        'success': True,
        'count': len(results),
        'locations': results
    })


@locations_bp.route('/api/location/<int:location_id>')
@login_required
def get_location_details(location_id):
    """Get detailed information about a specific location."""
    location = next((loc for loc in STANBIC_LOCATIONS if loc['id'] == location_id), None)
    
    if not location:
        return jsonify({
            'success': False,
            'message': 'Location not found'
        }), 404
    
    return jsonify({
        'success': True,
        'location': location
    })