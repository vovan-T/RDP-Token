import ast
import pathlib
import sys
from unittest.mock import MagicMock

source = pathlib.Path(sys.argv[1]).read_text()
tree = ast.parse(source)
function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'download_rdp')
function.decorator_list = []
connection = MagicMock()
target = {'name': 'CUBE', 'gateway_port': 60000}
connection.__enter__.return_value.execute.return_value.fetchone.return_value = target

def response(content, **kwargs):
    return content, kwargs

def abort(status):
    raise ValueError(status)

namespace = dict(client_identity=lambda: ({'serial': 'test'}, None),
                 db=lambda: connection, PUBLIC_RDP_HOST='rdp.example.test',
                 Response=response, abort=abort)
exec(compile(ast.Module(body=[function], type_ignores=[]), '<download_rdp>', 'exec'), namespace)
content, metadata = namespace['download_rdp'](1)
assert content == (
    'full address:s:rdp.example.test:60000\r\n'
    'prompt for credentials:i:0\r\n'
    'authentication level:i:2\r\n'
    'enablecredsspsupport:i:1\r\n'
    'redirectclipboard:i:1\r\n'
    'redirectsmartcards:i:0\r\n'
)
assert metadata['mimetype'] == 'application/x-rdp'
assert metadata['headers']['Content-Disposition'] == 'attachment; filename="CUBE.rdp"'
connection.__enter__.return_value.execute.return_value.fetchone.return_value = None
try:
    namespace['download_rdp'](2)
except ValueError as error:
    assert error.args == (404,)
else:
    raise AssertionError('Missing authorization target must be rejected')
print('PASS: RDP contents, credential prompt disabled, clipboard enabled, smartcards disabled, missing target rejected')
