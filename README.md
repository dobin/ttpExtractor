# ttpExtractor

Uses LLM to extract TTP's from CTI report PDFs. 
With focus on the P (Procedures). As in, what the threat actors were actually doing. 
For RedTeamers seeking to imitate TAs. 

Live at [ttpextractor.r00ted.ch](https://ttpextractor.r00ted.ch)

This project is more a experiment and playground, and not a reasonable
application.


It analyzes it in three ways: 
* ChatGPT 4o, paged
* Google Gemini 2.0, unpaged
* Google Gemini 2.5, unpaged


## Install

```
$ pip install -r requirements.txt
```

## Commandline 

```
$ export OPENAI_API_KEY="..."
$ export GEMINI_API_KEY="..."
$ cp ttp-test.pdf input/
$ python ./ttpextractor.py ttp-test.pdf
```

Result: 
```
$ ls output/ttp-test.pdf/
ttp-test.pdf_0_chunk.txt
ttp-test.pdf_0_response.txt
ttp-test.pdf_1_chunk.txt
ttp-test.pdf_1_response.txt
...
```

## Start Web UI

```
$ export OPENAI_API_KEY="..."
$ export UPLOAD_PW="..."
$ python ./web.py
```

Open `http://localhost:5000`.

