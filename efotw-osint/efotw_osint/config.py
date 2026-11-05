"""
Configuration, target URLs, indicator mappings, and OSINT entity resolution dictionaries.
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
REPORTS_DIR = BASE_DIR / "reports"
DB_PATH = DATA_DIR / "sovereign_watch.db"
MANIFEST_PATH = RAW_DIR / "manifest.json"
STATIC_DIR = Path(__file__).resolve().parent / "static"

# Primary Target OSINT Source (User-provided EFOTW Dataset Portal)
EFOTW_PORTAL_URL = (
    "https://efotw.org/economic-freedom/dataset"
    "?geozone=world&page=dataset&min-year=2&max-year=0&filter=0"
)
EFOTW_BASE_DOMAIN = "https://efotw.org"
EFOTW_FALLBACK_XLSX_URL = (
    "https://efotw.org/sites/all/modules/custom/ftw_maps_pages/files/"
    "efotw-2026-master-index-data-for-researchers-iso.xlsx"
)

# Live World Bank & Worldwide Governance Indicators (WGI) API Configuration
WB_API_BASE = "https://api.worldbank.org/v2"
WB_INDICATORS = {
    # World Development Indicators (Source 2)
    "wb_gdp_pcap_ppp": {
        "code": "NY.GDP.PCAP.PP.KD",
        "source": "2",
        "name": "GDP per Capita, PPP (Const. 2021 $)",
        "unit": "USD",
    },
    "wb_cpi_inflation": {
        "code": "FP.CPI.TOTL.ZG",
        "source": "2",
        "name": "Headline CPI Inflation (Annual %)",
        "unit": "%",
    },
    "wb_trade_gdp": {
        "code": "NE.TRD.GNFS.ZS",
        "source": "2",
        "name": "Trade Openness (% of GDP)",
        "unit": "% GDP",
    },
    "wb_mil_exp_gdp": {
        "code": "MS.MIL.XPND.GD.ZS",
        "source": "2",
        "name": "Military Expenditure (% of GDP)",
        "unit": "% GDP",
    },
    # Worldwide Governance Indicators (Source 3, 0-100 Score)
    "wgi_rule_of_law": {
        "code": "GOV_WGI_RL.SC",
        "source": "3",
        "name": "WGI Rule of Law Score (0-100)",
        "unit": "0-100",
    },
    "wgi_control_corruption": {
        "code": "GOV_WGI_CC.SC",
        "source": "3",
        "name": "WGI Control of Corruption (0-100)",
        "unit": "0-100",
    },
    "wgi_political_stability": {
        "code": "GOV_WGI_PV.SC",
        "source": "3",
        "name": "WGI Political Stability & No Violence (0-100)",
        "unit": "0-100",
    },
    "wgi_voice_accountability": {
        "code": "GOV_WGI_VA.SC",
        "source": "3",
        "name": "WGI Voice & Accountability (0-100)",
        "unit": "0-100",
    },
}

# Exact column mapping for Sheet 1: 'EFW Ratings' (header row index = 3)
# Maps exact Fraser Institute Excel headers (including original spacing/typos) to clean SQLite columns
EFW_RATINGS_COLUMN_MAP = {
    "Year": "year",
    "ISO_Code": "iso_code",
    "Countries": "country_name",
    "ECONOMIC FREEDOM ALL AREAS": "efw_score",
    "EFW RANK": "efw_rank",
    "EFW QUARTILE": "efw_quartile",
    # Area 1: Size of Government
    "1A Government consumption": "gov_consumption",
    "data": "gov_consumption_raw_pct",
    "1B  Transfers and subsidies": "transfers_subsidies",
    "data.2": "transfers_subsidies_raw_pct",
    "1C  Government investment": "gov_investment",
    "data.3": "gov_investment_raw_pct",
    "1D  Top marginal tax rate": "top_marginal_tax",
    "IE State ownership": "state_ownership",
    "Area 1 Size of Government": "area1_size_of_gov",
    "Area 1 Rank": "area1_rank",
    # Area 2: Legal System & Property Rights
    "2A  Judicial independence": "judicial_independence",
    "2B  Impartial courts": "impartial_courts",
    "2C  Property rights": "property_rights",
    "2D  Military interference": "military_interference",
    "2E Legal integrity": "legal_integrity",
    "2F Contracts": "contracts_enforcement",
    "2G Real property": "real_property",
    "2H Police and crime": "police_and_crime",
    "Gender Disparity Index": "gender_disparity_index",
    "Area 2 Legal System & Property Rights -- Without Gender Adjustment": "area2_legal_unadjusted",
    "Area 2 Legal System & Property Rights -- With Gender Adjustment": "area2_legal_property",
    "Area 2 Rank": "area2_rank",
    # Area 3: Sound Money
    "3A  Money growth": "money_growth",
    "data.6": "money_growth_raw_pct",
    "3B  Standard deviation of inflation": "inflation_stddev",
    "data.7": "inflation_stddev_raw",
    "3C  Inflation": "inflation_score",
    "data.8": "inflation_raw_pct",
    "3D  Foreign currency bank accounts": "foreign_currency_accounts",
    "Area 3 Sound Money": "area3_sound_money",
    "Area 3 Rank": "area3_rank",
    # Area 4: Freedom to Trade Internationally
    "4A  Tariffs": "tariffs",
    "data.10": "mean_tariff_raw_pct",
    "4B  Regulatory trade barriers": "regulatory_trade_barriers",
    "4C  Black market exchange rates": "black_market_fx",
    "4Di  Financial openness": "financial_openness",
    "4Dii  Capital controls": "capital_controls",
    "4Diii Freedom of foreigners to visit": "freedom_to_visit",
    "4Div Protection of Foreign Assets": "foreign_asset_protection",
    "4D  Controls of the movement of capital and people": "capital_people_controls",
    "Area 4 Freedom to trade internationally": "area4_trade_freedom",
    "Area 4 Rank": "area4_rank",
    # Area 5: Regulation
    "5Ai  Ownership of banks": "bank_ownership",
    "5Aii Private sector credit": "private_sector_credit",
    "5Aiii  Interest rate controls/negative real interest rates)": "interest_rate_controls",
    "5A  Credit market regulation": "credit_market_reg",
    "5Bvi  Conscription": "conscription",
    "5B  Labor market regulations": "labor_market_reg",
    "5Ci  Regulatory Burden": "regulatory_burden",
    "5Cii  Bureacracy costs": "bureaucracy_costs",
    "5Ciii  Impartial Public Administration": "impartial_public_admin",
    "5Civ Tax compliance": "tax_compliance",
    "5C  Business regulation": "business_reg",
    "5Di  Market openness": "market_openness",
    "5Diii Distorton of the business environment": "business_distortion",
    "5D Freedom to enter markets and compete": "market_entry_freedom",
    "Area 5 Regulation": "area5_regulation",
    "Area 5 Rank": "area5_rank",
    # Metadata
    "World Bank Region": "wb_region",
    "World Bank Current Income Classification, 1990-Present": "wb_income_group",
}

# Exact column mapping for Sheet 2: 'EFW Panel Dataset' (time-consistent longitudinal data)
EFW_PANEL_COLUMN_MAP = {
    "Year": "year",
    "ISO_Code": "iso_code",
    "Countries": "country_name",
    "ECONOMIC FREEDOM ALL AREAS Panel Data Set": "panel_efw_score",
    "Area 1: Size of Government": "panel_area1",
    "Area 2: Legal System & Property Rights": "panel_area2",
    "Area 3: Sound Money": "panel_area3",
    "Area 4: Freedom to Trade Internationally": "panel_area4",
    "Area 5: Regulation": "panel_area5",
    "Std. Dev. of Areas 1-5": "panel_area_stddev",
}

# OSINT Entity Resolution Map for historical country names (1950-1965 sheet & HTML aliases) -> ISO-3
HISTORICAL_ENTITY_RESOLUTION = {
    "Central Afr. Rep.": "CAF",
    "Congo, Dem. R.": "COD",
    "Congo, Rep. Of": "COG",
    "Cote d'Ivoire": "CIV",
    "Côte d'Ivoire": "CIV",
    "Czech Rep.": "CZE",
    "Dominican Rep.": "DOM",
    "Egypt": "EGY",
    "Hong Kong": "HKG",
    "Iran": "IRN",
    "Korea, South": "KOR",
    "Pap. New Guinea": "PNG",
    "Russia": "RUS",
    "Syria": "SYR",
    "Trinidad & Tob.": "TTO",
    "Turkey": "TUR",
    "Türkiye": "TUR",
    "Venezuela": "VEN",
}

# Human-readable labels for OSINT Sub-Indicators in UI & Dossiers
INDICATOR_LABELS = {
    "judicial_independence": ("Judicial Independence", "Area 2: Rule of Law"),
    "impartial_courts": ("Impartial Courts", "Area 2: Rule of Law"),
    "military_interference": ("No Military Interference", "Area 2: Rule of Law"),
    "property_rights": ("Property Rights Security", "Area 2: Rule of Law"),
    "legal_integrity": ("Legal System Integrity", "Area 2: Rule of Law"),
    "police_and_crime": ("Police Reliability & Crime Control", "Area 2: Rule of Law"),
    "impartial_public_admin": ("Impartial Public Administration", "Area 5: State Integrity"),
    "inflation_score": ("Price Stability (Low Inflation)", "Area 3: Monetary"),
    "inflation_stddev": ("Inflation Volatility Control", "Area 3: Monetary"),
    "money_growth": ("Monetary Growth Discipline", "Area 3: Monetary"),
    "foreign_currency_accounts": ("Foreign Currency Bank Freedom", "Area 3: Monetary"),
    "interest_rate_controls": ("Absence of Negative Real Rates", "Area 5: Monetary/Credit"),
    "black_market_fx": ("Absence of Black-Market FX Spread", "Area 4: Capital/FX"),
    "capital_controls": ("Capital Mobility (Low Controls)", "Area 4: Capital/FX"),
    "financial_openness": ("Financial Openness Index", "Area 4: Capital/FX"),
    "foreign_asset_protection": ("Foreign Asset Protection", "Area 4: Capital/FX"),
    "freedom_to_visit": ("Cross-Border Movement Freedom", "Area 4: Capital/FX"),
    "state_ownership": ("Absence of State Asset Capture", "Area 1: Coercion/State"),
    "bank_ownership": ("Private Banking Independence", "Area 5: Coercion/State"),
    "conscription": ("Absence of Military Conscription", "Area 5: Coercion/State"),
    "business_distortion": ("Non-Distorted Business Environment", "Area 5: Coercion/State"),
}
