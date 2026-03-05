import os
import re
from PIL import Image

# 1. Update app.py
app_py_path = 'backend/app.py'
with open(app_py_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Remove the global EMAIL_LOGO_SRC block (lines 21-31)
# We can do this with regex or string replacement
block_to_remove = """# --- Email Logo (base64 embedded for reliability) ---
import base64 as _base64
_logo_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'frontend', 'static', 'images', 'logo_email.png')
try:
    with open(_logo_path, 'rb') as _f:
        _logo_b64 = _base64.b64encode(_f.read()).decode('utf-8')
    EMAIL_LOGO_SRC = f"data:image/png;base64,{_logo_b64}"
except Exception:
    # Fallback to hosted URL if local file is unavailable
    EMAIL_LOGO_SRC = "{EMAIL_LOGO_SRC}"
"""
content = content.replace(block_to_remove, "")

# Replace the {EMAIL_LOGO_SRC} usage with a dynamic URL evaluated at request time
# Because each email function runs in a Flask request context (the API handlers), request.host_url is valid.
# Wait, I need to make sure `request` is imported. It is.
# I will replace {EMAIL_LOGO_SRC} with {request.host_url.rstrip(\'/\') + url_for(\'static\', filename=\'images/logo_email.png\')}
replacement_url = "{request.host_url.rstrip('/') + url_for('static', filename='images/logo_email.png')}"
content = content.replace("{EMAIL_LOGO_SRC}", replacement_url)

with open(app_py_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Updated app.py")

# 2. Update the logo image
src_image = 'C:/Users/Anjan.theeng/.gemini/antigravity/brain/8212c1d3-c44e-4955-bb0a-206991a7f9cb/media__1772727046641.png'
dest_image = 'frontend/static/images/logo_email.png'

# The user wants this specific image. We will resize it so it fits neatly the 60px height.
try:
    img = Image.open(src_image)
    # Calculate width to preserve aspect ratio at height 60
    aspect_ratio = img.width / img.height
    new_height = 60
    new_width = int(new_height * aspect_ratio)
    img_resized = img.resize((new_width, new_height), Image.LANCZOS)
    img_resized.save(dest_image)
    print(f"Resized and saved new logo to {dest_image}")
except Exception as e:
    print(f"Error processing image: {e}")
