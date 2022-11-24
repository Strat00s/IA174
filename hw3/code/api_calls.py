import requests

def APICall(difficulty: str, endpoint: str, uco:str, data: dict | None = None):
    url = f"https://ia174.fi.muni.cz/hw03/{difficulty}/{endpoint}/{uco}/"
    if data == None:
        request = requests.get(url)
    else:
        request = requests.post(url, json=data)
    
    if request.status_code != 200:
        print(f"Err {request.status_code}: {request.reason}")
        return None

    return  request.json()
