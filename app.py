# app.py
from flask import Flask, render_template, request, send_file, after_this_request
import os
from analyzer import analyze_log_file

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 612 * 1024 * 1024  # 612MB max file size (increased from 16MB)
app.config['ALLOWED_EXTENSIONS'] = {'log', 'txt'}  # Only allow these file types

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('reports', exist_ok=True)

def allowed_file(filename):
    """Check if the uploaded file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/', methods=['GET', 'POST'])
def index():
    results = None
    filename = None
    
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'logfile' not in request.files:
            return render_template('index.html', error='No file selected.')
        
        file = request.files['logfile']
        if file.filename == '':
            return render_template('index.html', error='No file selected.')
        
        if file and allowed_file(file.filename):
            try:
                # Save the uploaded file
                filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                file.save(filename)
                
                # Analyze the log file
                results = analyze_log_file(filename)
                
                # Clean up the uploaded file after analysis
                try:
                    os.remove(filename)
                except:
                    pass
                
                # Pass results to the template
                return render_template('index.html', results=results, original_filename=file.filename)
            
            except Exception as e:
                # Clean up if error occurs
                try:
                    os.remove(filename)
                except:
                    pass
                return render_template('index.html', error=f'Error processing file: {str(e)}')
        else:
            return render_template('index.html', error='Invalid file type. Please upload .log or .txt files.')
    
    return render_template('index.html', results=results)

@app.route('/download_report/<filename>')
def download_report(filename):
    """Allows users to download the generated CSV report."""
    try:
        # Security check: prevent directory traversal
        if '..' in filename or filename.startswith('/'):
            return "Invalid filename", 400
            
        path = os.path.join('reports', filename)
        if not os.path.exists(path):
            return "Report not found.", 404
            
        return send_file(path, as_attachment=True, download_name=f"security_report_{filename}")
    except FileNotFoundError:
        return "Report not found.", 404

# Add favicon route to prevent 404 errors
@app.route('/favicon.ico')
def favicon():
    return '', 204  # Return no content

if __name__ == '__main__':
    # Run on all interfaces so you can access from other devices
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
