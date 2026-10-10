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

### Using Poetry (recommended)

```
$ poetry install
```

### Using pip

```
$ pip install -r requirements.txt
```

## Commandline 

```
$ cat > .env <<'EOF'
OPENAI_API_KEY=...
GEMINI_API_KEY=...
UPLOAD_PW=...
EOF
$ cp ttp-test.pdf input/
$ poetry run python ./ttpextractor.py ttp-test.pdf
```

The application loads these variables from `.env` in the project directory.
Variables already exported in the environment take precedence. Do not commit
`.env`, since it contains secrets.

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
$ poetry run python ./web.py
```

Open `http://localhost:5000`.

