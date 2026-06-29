import pandas as pd
import requests
import urllib3

urllib3.disable_warnings()

SNIPEIT_URL = "https://ocam.ocsports.com.my"
API_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiIxIiwianRpIjoiNWRkMjk3ODA3ZDZkOTI5N2RhMzFhOTEzODNmNDhhMGRlYTQ4MjgwZDE4NGRkOGI1OGQxMzQ4ZTFiOTFjMDFmMTY5OGUwOTMxNGRjNTI4YzYiLCJpYXQiOjE3ODEwMDE2OTUuNzMwODU4LCJuYmYiOjE3ODEwMDE2OTUuNzMwODYxLCJleHAiOjIyNTQzODcyOTUuNjg0OTYsInN1YiI6IjMiLCJzY29wZXMiOltdfQ.zaMURmaYofv-pGZZRPSo1FFTZb-iY72nXFvDUBHTYW7dIrO16t7l0R10dVkLEjKhfIyFQFIzFfqlGc6TYJYPaL6JJvgxN3AKSp36B5Q7vJxGskRgbRgJB5fvQTUNTo1s8_BdzXjAqoKOrnh_BkhAq2YDYlq0AG1RiFe1vsf6fUkFWt_Gvnm7FUyiAdq9OE_X6yPHvLwCZwymqXaewsOYjMc0EJtwiIFrqy0XW3kUnFS5pfZJVaFj7OzGgvTpTFPiW61GD3GXkgqOOuNpruZ_lFJoT-9H85hANyA3GXq4B7WQHYoMFjQUlbbCJ5qEKyRNHLqgjlri5sA4EYRqG7xlwcrqGfhhRqGBW89ygDeQoulr5LlFdoW7SQsMHTVsW2aplD0-Hnl8mZWF2g4UOjepg4VvP9vUmmYdAwWKobwSWdoWKfCmNhRunimDHwdNWM2XSZtBSUwtwt_Y4-pLAZJKgUZ5Vj5ngAAkwoYtnaneASn7KcrUsjIFD6ipeePF_bQBWtnJifc6ae8Ouvz6MrzWl3UIg409zgKu7-7-Evv5rmVtvN0_oMMWDr1wKvmVzVU-Z6f19su3AJyDmJK4yODlwCAIgx10mNBfBynvjLDMDFMl43sqKSTOt84L_QCK098FMnvZORmBaV8jbvyy1DxBvAXO9NgWJeQFALk3kLoyNrU"

CSV_FILE = r"C:\ocam\Test\bluetooth_scanner_import_updated.csv"

headers = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

df = pd.read_csv(CSV_FILE)
df.columns = df.columns.str.strip()

print("CSV columns:")
print(df.columns.tolist())

for index, row in df.iterrows():
    asset_tag = str(row["asset_tag"]).strip()
    date_given = str(row["Date Given"]).strip()
    notes = str(row["Notes"]).strip()

    if not asset_tag or asset_tag.lower() == "nan":
        print(f"\nSkipping row {index + 1}: missing asset_tag")
        continue

    print(f"\nProcessing row {index + 1}: {asset_tag}")
    print("Date Given:", date_given)
    print("Notes:", notes)

    search_response = requests.get(
        f"{SNIPEIT_URL}/api/v1/hardware",
        headers=headers,
        params={"search": asset_tag},
        verify=False
    )

    print("Search Status:", search_response.status_code)

    if search_response.status_code != 200:
        print(search_response.text)
        continue

    search_data = search_response.json()

    if search_data.get("total", 0) == 0:
        print("Asset not found")
        continue

    asset_id = search_data["rows"][0]["id"]
    found_asset_tag = search_data["rows"][0].get("asset_tag", "")

    print("Found Asset Tag:", found_asset_tag)
    print("Asset ID:", asset_id)

    update_response = requests.patch(
        f"{SNIPEIT_URL}/api/v1/hardware/{asset_id}",
        headers=headers,
        json={
            "_snipeit_date_given_18": date_given,
            "notes": notes
        },
        verify=False
    )

    print("Update Status:", update_response.status_code)
    print(update_response.text)

print("\nFinished updating all rows.")