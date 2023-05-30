from flask import Flask, request

app = Flask(__name__)

@app.route("/", methods=['GET', 'POST'])
def hello_world():
    if request.method == 'POST':
        pwd = request.form['password']
        return f"<h1>Your Password: {pwd}</h1>"
    
    return "<form action='' method='POST'><input name='password' type='password' placeholder='Password'/><input type='submit' value='Login'/></form>"


if __name__=="__main__":
    app.run(debug=True, port=80)