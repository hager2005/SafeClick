# SafeClick-URL-Checker

SafeClick is an Arabic web-based URL safety checker built with Flask, SQLite, HTML, CSS, and JavaScript. The initial version uses transparent rule-based analysis and does not claim that a link is definitely safe.

## Run

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

## Features

- Rule-based URL analysis
- Safe, suspicious, and potentially dangerous classifications
- Reasons explaining the result
- SQLite scan history and statistics
- Responsive Arabic interface

Important: this is a preliminary heuristic checker and should not be treated as definitive security verification.
