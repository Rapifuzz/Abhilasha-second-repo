from django.core.management.base import BaseCommand,CommandError
import os

dirs = [
    "media/",
    "archive",
    "media/csvfiles",
    "media/pdfs",
    "media/compare",
    "media/swaggerfiles",
    "media/wsdlinputfiles",
    "media/mitm_csvfiles"
    ]

def general_directory(list_of_directory):

    for dir in list_of_directory:
        try:
            os.makedirs(dir,exist_ok=True)    
        except Exception as e:
            pass

class Command(BaseCommand):

    """Command for creating a new directory
     for logs."""
    
    help = "Create directory for logs "
    def handle(self, *args, **kwargs):
        try:
            general_directory(dirs)
        except Exception as e:
            raise CommandError("Failed to create directory",e)
        self.stdout.write("Creating media directory >>> >>>")