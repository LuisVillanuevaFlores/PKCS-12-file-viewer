import os

from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.serialization import pkcs12
from OpenSSL import crypto
from flask import Flask
from flask import flash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from flask import render_template
from flask import redirect
from wtforms.fields import FileField
from wtforms.fields import PasswordField
from wtforms.fields import SubmitField
from werkzeug.utils import secure_filename
from wtforms.fields import URLField
from flask_wtf.file import FileAllowed
from flask_wtf.file import FileRequired
from wtforms.validators import DataRequired

app = Flask(__name__,
template_folder='./templates',
static_folder='./static')


bootstrap = Bootstrap(app)

class KeyForm(FlaskForm):
    key = FileField(validators=[
        FileRequired(),
        FileAllowed(['p12'], "Debe seleccionar un archivo .p12")
    ])
    pwd = PasswordField('Ingrese el password', validators=[DataRequired()])
    submit = SubmitField('Cargar Fichero')

@app.route('/', methods=['GET', 'POST'])
def index():
    key_form = KeyForm()
    data = {}
    context = {
        'key_form':key_form,
        'data': data
    }
    if key_form.validate_on_submit():
        file = key_form.key.data
        pwd = key_form.pwd.data
        file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),secure_filename(file.filename)))
        if file:
            try:
                private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(open('./'+file.filename, "rb").read(), bytes(pwd, 'utf-8'))
            except ValueError as ve:
                if('Could not deserialize PKCS12 data' in str(ve)):
                    flash("No es un fichero válido")
                if('Invalid password or PKCS12 data' in str(ve)):
                    flash("Contraseña no válida")
                return redirect('/')

            private_numbers = private_key.private_numbers()
            private_numbers_public = private_numbers.public_numbers

            if private_numbers:
                data.update({
                    'modulus': private_numbers_public.n,
                    'publicExponent': private_numbers_public.e,
                    'privateExponent': private_numbers.d,
                    'prime1': private_numbers.p,
                    'prime2': private_numbers.q,
                    'exponent1': private_numbers.dmp1,
                    'exponent2': private_numbers.dmq1,
                    'coefficient': private_numbers.iqmp,
                })
                context['data'] = data
                print("privada")
            else:
                data.update({
                    'type': 'public',
                    'modulus': key.n,
                    'publicExponent': key.e,
                })
                context['data'] = data
    return render_template('index.html', **context)

if __name__=='__main__':
    app.config['WTF_CSRF_ENABLED']= False
    app.config['SECRET_KEY']='KEY_SECRET'
    app.config['ENV']='development'
    app.run(debug=True)