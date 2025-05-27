import sys
import os
import re
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
import json
import threading

from ttpextractor import ProcessUpload

app = Flask(__name__)

UPLOAD_FOLDER = 'input'
OUTPUT_FOLDER = 'output'
ALLOWED_EXTENSIONS = {'pdf', 'txt'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'your_secret_key'  # Needed for flash messages
app.config['UPLOAD_PW'] = os.getenv('UPLOAD_PW')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)


def allowed_file(filename):
    if not '.' in filename:
        return False
    if not filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS:
        return False
    if not secure_filename(filename) == filename:
        return False
    return True


def process_file(filename):
    ProcessUpload(filename, details=True)


@app.route('/')
def home():
    output_dirs = os.listdir('output/')
    output_dirs.sort()
    return render_template('index.html', title="Flask App", projects=output_dirs)


@app.route('/about')
def about():
    return render_template('about.html', title="Flask App")


@app.route('/project/<project_name>')
def project(project_name):
    project_dir = os.path.join('output', project_name)
    if not os.path.exists(project_dir):
        flash(f'Project "{project_name}" not found')
        return redirect(url_for('home'))
    

    # ChatGPT chunked
    files = os.listdir(project_dir)
    files.sort()
    elements = {}
    for file in files:
        # Get the number from the filename
        i = 0
        match = re.search(r'_(\d+)_', file)
        if match:
            number = match.group(1)
            i = int(number)
        else:
            # Skip files that don't have a number in the filename
            continue

        print("Handle: {} {}".format(i, file))

        data = ""
        with open(os.path.join(project_dir, file), 'r', encoding="utf-8") as f:
            data = f.read()
        #data = data.replace("\n", "<br>")

        if i not in elements:
            elements[i] = {}

        elements[i]["name"] = file
        elements[i]["idx"] = i
        if 'chunk' in file:
            elements[i]["text"] = data
        elif 'response' in file:
            elements[i]["response"] = data
    ordered_elements = elements.values()
    ordered_elements = sorted(ordered_elements, key=lambda x: x["idx"])

    # aggregated chunks
    aggregated_chunks_file = os.path.join(project_dir, project_name + "_aggregated_chunks.txt")
    aggregated_chunks = ""
    if os.path.exists(aggregated_chunks_file):
        with open(aggregated_chunks_file, 'r', encoding="utf-8") as f:
            aggregated_chunks = f.read()
    #full_text = aggregated_chunks.replace("\n", "<br>")
    full_text = aggregated_chunks

    # gemini
    gemini20_file = os.path.join(project_dir, project_name + "_gemini20.txt")
    if os.path.exists(gemini20_file):
        with open(gemini20_file, 'r', encoding="utf-8") as f:
            gemini20_output = f.read()
    gemini25_file = os.path.join(project_dir, project_name + "_gemini25.txt")
    if os.path.exists(gemini25_file):
        with open(gemini25_file, 'r', encoding="utf-8") as f:
            gemini25_output = f.read()
    #gemini20_output = gemini20_output.replace("\n", "<br>")
    #gemini25_output = gemini25_output.replace("\n", "<br>")

    # check if we have some more infos
    metadata_file = os.path.join(
        app.config['UPLOAD_FOLDER'], project_name + '.json')
    metadata = None
    if os.path.exists(metadata_file):
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)

    return render_template('project.html', 
        title=project_name, 
        project_name=project_name,
        metadata=metadata,
        full_text=full_text,
        elements=ordered_elements,
        gemini20_output=gemini20_output,
        gemini25_output=gemini25_output,
    )


@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    # Display?
    if request.method == 'GET':
        return render_template('upload.html')

    # PW check
    password = request.form.get('password', 'default')
    if password != app.config['UPLOAD_PW']:
        flash('Invalid password')
        return redirect(request.url)

    # file related
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if not file or not allowed_file(file.filename):
        flash('File type not allowed')
        return redirect(request.url)

    # save file
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    
    # save file metadata
    note = request.form.get('note', '')
    url = request.form.get('url', '')
    metadata = {
        'note': note,
        'url': url,
    }
    with open(filepath + ".json", 'w') as f:
        json.dump(metadata, f)

    # start processing the upload in the background
    thread = threading.Thread(target=process_file, args=(file.filename,))
    thread.start()
    
    flash(f'File "{file.filename}" uploaded successfully!')
    return redirect(url_for('home'))


@app.route('/download/<project_name>')
def download(project_name):
    if not project_name == secure_filename(project_name):
        flash('Invalid project name')
        return redirect(url_for('home'))

    project_dir = os.path.join('input', project_name)
    if not os.path.exists(project_dir):
        flash(f'Project "{project_name}" not found')

    filepath = "input/" + project_name
    return send_file(filepath, as_attachment=True)


if __name__ == '__main__':
    if len(sys.argv) > 1:
        if sys.argv[1] == "prod":
            print("ttpExtractor: Prod")
            app.run(host='0.0.0.0', debug=False)
    else:
        print("ttpExtractor: Debug")
        app.run(debug=True)
