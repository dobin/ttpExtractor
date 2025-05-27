import os
from typing import List

from openai import OpenAI
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.schema import Document
from model import Chonk

client_openai = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

MODEL = "gpt-4o"

chunk_overlap = 100
chunk_size_full = 30000  # Covers most articles. Needs 4o (context size)
chunk_size_details = 2048  # reasonable size for detais


def ProcessUpload_openai(filename, prompt, details):
    print(f"Processing {filename} with model {MODEL}")

    results = openai_handle_file(filename, prompt, details=details)
    write_results(results, filename)


def openai_handle_file(filename: str, prompt: str, details: bool):
    results = []
    chonks = None

    #print("Handle file: {}".format(filename))
    
    filepath = "input/" + filename
    if not os.path.exists(filepath):
        print(f"File {filepath} does not exist")
        return results
    if filename.endswith(".pdf"):
        if details:
            chonks = pdf_chonks_detailed(filepath)
        else:
            chonks = pdf_chonks_summary(filepath)
    elif filename.endswith(".txt"):
        if details:
            chonks = txt_chunks(filepath, chunk_size=chunk_size_details)
        else:
            chonks = txt_chunks(filepath, chunk_size=chunk_size_full)

    #print("Chonks: {}  (details: {})".format(
    #    len(chonks),
    #    details))
    
    for i, chonk in enumerate(chonks):
        chunk_content = chonk.text
        #print("  Handle Chonk {}  (size: {})".format(
        #    i, len(chunk_content)
        #))
        
        response = ask_chatgpt(chunk_content, prompt)
        chonk.response = response

    return chonks


def ask_chatgpt(text, prompt):
    response = client_openai.responses.create(
        model=MODEL,
        instructions=prompt,
        input=text
    )
    return response.output_text


# PDF Summary
#   Extract ALL text of PDF, and chunk it
def pdf_chonks_summary(filename) -> List[Chonk]:
    #print("Filetype: PDF Summary")
    loader = PyPDFLoader(filename)
    pages = loader.load()
    
    # Extract text from all pages
    all_text = "\n\n".join(page.page_content for page in pages)
    
    # Create chunks
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size_full,
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", " "]  # Ensure proper word separation
    )
    chunks = text_splitter.split_text(all_text)

    chonks = []
    for i, chunk in enumerate(chunks):
        content = chunk.page_content
        chonks.append(Chonk(content, [i]))

    return chonks


# PDF Detailed
#   One chunk per page (small pages merged)
def pdf_chonks_detailed(filename) -> List[Chonk]:
    #print("Filetype: PDF Detailed")
    loader = PyPDFLoader(filename)
    pages = loader.load()
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size_full, # per page, should never be reached 
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", " "]
    )
    chunks = text_splitter.split_documents(pages)

    # Now generate the chonks
    # if multiple plages with little text appear, merge them.
    # otherwise, just add each page

    chonks = []
    cutoff = 768  # heuristic, adjust?
    smol_data = None
    smol_pages = []
    for i, chunk in enumerate(chunks):
        content = chunk.page_content

        if len(content) > cutoff:
            # page with enough data
            chonks.append(Chonk(content, [i]))
            #print("Chonk {}: Big: Add ({})".format(
            #    i, len(content)
            #))
            
            if smol_data is not None:
                #print("Chonk {}: Smol Previous: Add ({}, pages: {})".format(
                #    i, len(smol_data), str(smol_pages)
                #))

                # add previous if necessary
                chonks.append(Chonk(smol_data, [i]))
                smol_data = None
                smol_pages = []

        else:
            if smol_data is None:
                smol_data = content
                smol_pages = [ i ]
            else:
                smol_data += "\n" + content
                smol_pages.append(i)

                if len(smol_data) > cutoff:
                    #print("Chonk {}: Smol summary: Add ({}, pages: {})".format(
                    #    i, len(smol_data), str(smol_pages)
                    #))

                    chonks.append(Chonk(smol_data, smol_pages))
                    smol_data = None
                    smol_pages = []

    return chonks


def txt_chunks(filename, chunk_size) -> List[Chonk]:
    #print("Filetype: TXT")
    with open(filename, "r", encoding="utf-8") as file:
        text = file.read()
    doc = Document(page_content=text)
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size, 
        chunk_overlap=chunk_overlap)
    chunks = text_splitter.split_documents([doc])

    chonks = []
    for i, chunk in enumerate(chunks):
        content = chunk.page_content
        chonks.append(Chonk(content, [i]))

    return chonks


def write_results(chonks: List[Chonk], basename):
    basedir = "output/" + basename
    os.makedirs(basedir, exist_ok=True)

    aggregated_chunks = ""
    aggregated_responses = ""
    base_path = "output/" + basename + "/" + basename +"_" # ouutput/dfir-bla/dfir-bla_
    print("  -> write results to: " + base_path)

    diiir = "output/" + basename + "/"
    for file in os.listdir(diiir):
        os.remove(os.path.join(diiir, file))

    for i, chonk in enumerate(chonks):
        chunk = chonk.text
        response = chonk.response

        aggregated_chunks += chunk + "\n"
        aggregated_responses += response + "\n"

        filepath_base = base_path + str(i) + "_"

        filename_chunk = filepath_base + "chunk.txt"
        filename_response = filepath_base + "response.txt"

        with open(filename_chunk, "w", encoding="utf-8") as file:
            file.write(chunk)
        with open(filename_response, "w", encoding="utf-8") as file:
            file.write("# Model: {}\r\n".format(MODEL))
            file.write(response)

    with open(base_path + "aggregated_chunks.txt", "w", encoding="utf-8") as file:
        file.write(aggregated_chunks)
    with open(base_path + "aggregated_responses.txt", "w", encoding="utf-8") as file:
        file.write("# Model: {}\r\n".format(MODEL))
        file.write(aggregated_responses)

