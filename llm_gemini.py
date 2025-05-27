from google import genai
from google.genai import types
import pathlib
import os

client_gemini = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))


def ProcessUpload_gemini(basename, prompt, type):
    if type == "gemini20":
        model = "gemini-2.0-flash"
    elif type == "gemini25":
        model = "gemini-2.5-flash-preview-05-20"
    else:
        raise ValueError(f"Unknown type: {type}")
    
    print(f"Processing {basename} with model {model}")

    results_text  = ask_gemini(basename, prompt, model)
    mypath = "output/" + basename + "/" + basename +"_" + type + ".txt"
    print(f"  -> writing results to {mypath}")
    with open(mypath, 'w') as f:
        f.write("# Model: {}\r\n".format(model))
        f.write(results_text)


def ask_gemini(filename, prompt: str, model: str):
    filepath = pathlib.Path("input/" + filename)
    response = client_gemini.models.generate_content(
        #model="gemini-2.0-flash",
        #model="gemini-2.5-flash-preview-05-20",
        model=model,
        contents=[
            types.Part.from_bytes(
                data=filepath.read_bytes(),
                mime_type='application/pdf',
            ),
            prompt])
    return response.text


