import os
from flask import Flask, render_template, request

app = Flask(__name__)

# Define the base directory for the file manager
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


@app.route('/')
def list_files():
    current_dir = request.args.get('dir', 'documents')

    # List files and directories in the current directory
    items = os.listdir(current_dir)

    # Separate files and directories
    files = []
    directories = []

    for item in items:
        item_path = os.path.join(current_dir, item)
        if os.path.isfile(item_path):
            files.append(item)
        else:
            directories.append(item)

    return render_template('index.html', current_dir=current_dir, files=files, directories=directories)


@app.route('/read_file')
def read_file():
    file_path = request.args.get('file')
    if file_path:
        with open(file_path, 'r') as file:
            file_content = file.read()
        return '<pre style="background: gray; padding: 1rem 2rem">' + file_content + '</pre>'
    return 'File not found.'


if __name__ == '__main__':
    app.run(debug=True)
