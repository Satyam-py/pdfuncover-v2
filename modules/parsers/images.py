# modules/parsers/images.py
#
# Image extraction via pdfimages.
#
# Moved verbatim from the "IMAGE EXTRACTION" section of the former
# extract_embedded_objects() — no logic changed.

import os
import shutil
import logging

from modules.parsers.helpers import run_command


# ==========================================
# LOGGING SETUP
# ==========================================

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    filename="logs/embedded_extraction.log",
    level=logging.ERROR,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

log = logging.getLogger(__name__)


def extract_images(pdf_path):
    """
    List and extract images embedded in the PDF using pdfimages.

    Returns the same "Images" dict the original
    extract_embedded_objects() produced.
    """

    image_data = {
        "Images Found": False,
        "Image Count": 0,
        "Images Extracted": False,
        "Extracted To": "None",
        "Parser Errors": []
    }

    output_dir = "output/images"
    os.makedirs(output_dir, exist_ok=True)

    if shutil.which("pdfimages"):

        try:

            list_output = run_command(
                ["pdfimages", "-list", pdf_path]
            )

            image_count = 0

            for line in list_output.splitlines():

                line = line.strip()

                if (
                    not line
                    or line.startswith("page")
                    or line.startswith("-")
                ):
                    continue

                if line.startswith("Syntax Error"):
                    image_data["Parser Errors"].append(line)
                    continue

                cols = line.split()

                if cols and cols[0].isdigit():
                    image_count += 1

            image_data["Image Count"] = image_count
            image_data["Images Found"] = image_count > 0

            if image_count > 0:

                pdf_name = os.path.splitext(
                    os.path.basename(pdf_path)
                )[0]

                image_prefix = os.path.join(
                    output_dir,
                    pdf_name
                )

                run_command([
                    "pdfimages",
                    "-all",
                    pdf_path,
                    image_prefix
                ])

                image_data["Images Extracted"] = True
                image_data["Extracted To"] = output_dir

        except Exception as e:

            log.error(f"Image extraction failed: {e}")
            image_data["Error"] = str(e)

    else:

        image_data["Error"] = "pdfimages not installed"

    return image_data
