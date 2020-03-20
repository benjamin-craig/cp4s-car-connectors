import sys, argparse, traceback

from car_framework.context import context
from car_framework.app import BaseApp

from server_access import AssetServer
from full_import import FullImport
from inc_import import IncrementalImport


version = '1.0.1'


class App(BaseApp):
    def __init__(self):
        super().__init__('This script is used for pushing asset data to CP4S CAR ingestion microservice')
        self.parser.add_argument('-server', dest='server', type=str, required=True, help='The url of the Asset data server')
        self.parser.add_argument('-username', dest='username', type=str, required=True, help='The user name for the Asset data server')
        self.parser.add_argument('-password', dest='password', type=str, required=True, help='The password for the Asset data server')


    def source(self):
        return 'ReferenceConnectorAssetModel'


    def setup(self):
        super().setup()
        context().asset_server = AssetServer()
        context().full_importer = FullImport()
        context().inc_importer = IncrementalImport()


app = App()
app.setup()
app.run()
