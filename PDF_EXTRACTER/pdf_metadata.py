#!/usr/bin/env python3

import PyPDF2
import sys
import re
import io
import os
import struct
from datetime import datetime
from xml.etree import ElementTree as ET

def get_permissions_info(pdf_reader):
    """
    Get the permissions information from the PDF
    
    Args:
        pdf_reader: PyPDF2.PdfReader object
        
    Returns:
        dict: Dictionary containing permissions information
    """
    permissions = {}
    
    # Check for each permission attribute before accessing
    permission_attrs = [
        "can_print", "can_modify", "can_copy", "can_annotate", 
        "can_fill_forms", "can_extract_content", "can_assemble", "can_print_degraded"
    ]
    
    for attr in permission_attrs:
        if hasattr(pdf_reader, attr):
            permissions[attr.replace("can_", "").replace("_", " ").title()] = getattr(pdf_reader, attr)
    
    return permissions

def extract_xmp_metadata(pdf_reader):
    """
    Extract XMP metadata from the PDF if available
    
    Args:
        pdf_reader: PyPDF2.PdfReader object
        
    Returns:
        dict: Dictionary containing XMP metadata
    """
    xmp_metadata = {}
    
    # Check if the XMP metadata attribute exists
    if hasattr(pdf_reader, 'xmp_metadata') and pdf_reader.xmp_metadata:
        try:
            xmp = pdf_reader.xmp_metadata
            
            # Define XML namespaces commonly used in XMP
            namespaces = {
                'dc': 'http://purl.org/dc/elements/1.1/',
                'pdf': 'http://ns.adobe.com/pdf/1.3/',
                'xmp': 'http://ns.adobe.com/xap/1.0/',
                'xmpMM': 'http://ns.adobe.com/xap/1.0/mm/',
                'pdfaid': 'http://www.aiim.org/pdfa/ns/id/',
                'pdfuaid': 'http://www.aiim.org/pdfua/ns/id/',
                'pdfx': 'http://ns.adobe.com/pdfx/1.3/',
                'pdfaExtension': 'http://www.aiim.org/pdfa/ns/extension/',
                'pdfaSchema': 'http://www.aiim.org/pdfa/ns/schema#',
                'pdfaProperty': 'http://www.aiim.org/pdfa/ns/property#',
                'prism': 'http://prismstandard.org/namespaces/basic/2.0/',
                'photoshop': 'http://ns.adobe.com/photoshop/1.0/',
                'xmpTPg': 'http://ns.adobe.com/xap/1.0/t/pg/',
                'stFnt': 'http://ns.adobe.com/xap/1.0/sType/Font#',
                'stEvt': 'http://ns.adobe.com/xap/1.0/sType/Event#'
            }
            
            # Try to extract common metadata fields from XMP
            if hasattr(xmp, 'raw_xmp'):
                try:
                    root = ET.fromstring(xmp.raw_xmp)
                    
                    # Extract Dublin Core properties that might contain owner info
                    for tag in ['creator', 'publisher', 'rights', 'rightsHolder', 'owner']:
                        for ns, uri in namespaces.items():
                            xpath = f'.//{{{uri}}}{tag}'
                            elements = root.findall(xpath)
                            if elements:
                                for elem in elements:
                                    if elem.text:
                                        xmp_metadata[f"XMP {ns}:{tag}"] = elem.text
                                        
                except Exception as e:
                    xmp_metadata['XMP Parsing Error'] = str(e)
            
            # Try to access specific XMP attributes directly
            xmp_fields = [
                ('dc:creator', 'Creator'),
                ('dc:publisher', 'Publisher'),
                ('dc:rights', 'Rights'),
                ('pdf:Producer', 'Producer'),
                ('pdf:Keywords', 'Keywords'),
                ('xmp:CreatorTool', 'Creator Tool'),
                ('xmp:CreateDate', 'Create Date'),
                ('xmp:ModifyDate', 'Modify Date'),
                ('xmp:MetadataDate', 'Metadata Date'),
                ('xmpMM:DocumentID', 'Document ID'),
                ('xmpMM:InstanceID', 'Instance ID'),
                ('photoshop:AuthorsPosition', 'Author Position'),
                ('photoshop:CaptionWriter', 'Caption Writer'),
                ('xmpRights:Owner', 'Owner'),
                ('xmpRights:UsageTerms', 'Usage Terms'),
                ('xmpRights:WebStatement', 'Web Statement'),
                ('pdfaid:part', 'PDF/A Part'),
                ('pdfaid:conformance', 'PDF/A Conformance')
            ]
            
            for xmp_field, display_name in xmp_fields:
                if hasattr(xmp, xmp_field.replace(':', '_')):
                    value = getattr(xmp, xmp_field.replace(':', '_'))
                    if value:
                        xmp_metadata[f"XMP {display_name}"] = value
        
        except Exception as e:
            xmp_metadata['XMP Extraction Error'] = str(e)
    
    return xmp_metadata

def extract_additional_info_dict_entries(pdf_reader):
    """
    Extract additional entries from the document info dictionary
    
    Args:
        pdf_reader: PyPDF2.PdfReader object
        
    Returns:
        dict: Dictionary containing additional info dict entries
    """
    additional_info = {}
    
    try:
        if hasattr(pdf_reader, 'metadata') and pdf_reader.metadata:
            # Look for custom or additional fields that might contain owner info
            for key, value in pdf_reader.metadata.items():
                # Skip standard fields we already process
                if key in ['/Title', '/Author', '/Creator', '/Producer', '/Subject', '/Keywords', 
                          '/CreationDate', '/ModDate']:
                    continue
                    
                # Check for owner-related keys
                field_name = key.replace('/', '')
                additional_info[field_name] = value
                
            # Specifically look for owner-related fields
            owner_fields = ['/Owner', '/DocumentOwner', '/Copyright', '/CopyrightOwner', 
                           '/CopyrightInfo', '/Company', '/Manager', '/Contact']
                           
            for field in owner_fields:
                if field in pdf_reader.metadata:
                    additional_info[field.replace('/', '')] = pdf_reader.metadata[field]
    
    except Exception as e:
        additional_info['Info Dict Error'] = str(e)
    
    return additional_info

def parse_pdf_date(date_string):
    """
    Parse PDF date format to a more readable format
    
    Args:
        date_string (str): PDF date string
        
    Returns:
        str: Formatted date string or the original if parsing fails
    """
    if not date_string or date_string == 'Not available':
        return date_string
        
    try:
        # Extract digits from the PDF date format D:YYYYMMDDHHmmSSOHH'mm'
        match = re.match(r'D:(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})([-+])(\d{2})[\':]?(\d{2})?', date_string)
        if match:
            year, month, day, hour, minute, second, sign, offset_hour, offset_minute = match.groups()
            formatted_date = f"{year}-{month}-{day} {hour}:{minute}:{second}"
            if sign and offset_hour:
                formatted_date += f" {sign}{offset_hour}"
                if offset_minute:
                    formatted_date += f":{offset_minute}"
            return formatted_date
    except Exception:
        pass
        
    return date_string

def extract_raw_metadata_from_file(file_path):
    """
    Extract metadata by examining the raw PDF file
    
    Args:
        file_path (str): Path to the PDF file
        
    Returns:
        dict: Dictionary containing additional metadata extracted from raw PDF
    """
    raw_metadata = {}
    
    try:
        # Read the file in binary mode
        with open(file_path, 'rb') as file:
            # Read the entire file content
            content = file.read()
            
            # Look for potential metadata markers in the raw PDF content
            metadata_markers = [
                (b'/Owner', 'Raw Owner'),
                (b'/DocumentOwner', 'Raw Document Owner'),
                (b'/Author', 'Raw Author'),
                (b'/Creator', 'Raw Creator'),
                (b'/Company', 'Raw Company'),
                (b'/Copyright', 'Raw Copyright'),
                (b'/Manager', 'Raw Manager'),
                (b'/Contact', 'Raw Contact'),
                (b'/LastModifiedBy', 'Raw Last Modified By')
            ]
            
            for marker, label in metadata_markers:
                # Look for the marker in the file content
                pos = content.find(marker)
                if pos != -1:
                    # Extract the value after the marker
                    # PDF syntax: /Key (Value) or /Key /Value or /Key <hex>
                    start = pos + len(marker)
                    
                    # Skip whitespace
                    while start < len(content) and content[start:start+1].isspace():
                        start += 1
                    
                    if start < len(content):
                        if content[start:start+1] == b'(':
                            # Value is a string in parentheses
                            end = start + 1
                            # Find the matching closing parenthesis, accounting for nested parentheses
                            paren_depth = 1
                            while end < len(content) and paren_depth > 0:
                                if content[end:end+1] == b'(':
                                    paren_depth += 1
                                elif content[end:end+1] == b')':
                                    paren_depth -= 1
                                end += 1
                            
                            if end > start + 1:
                                try:
                                    # Decode as UTF-8, fallback to Latin-1
                                    value = content[start+1:end-1].decode('utf-8', errors='replace')
                                    raw_metadata[label] = value
                                except Exception:
                                    pass
                                    
                        elif content[start:start+1] == b'<':
                            # Value is a hex string
                            end = content.find(b'>', start)
                            if end != -1:
                                try:
                                    # Convert hex to bytes, then to string
                                    hex_str = content[start+1:end].decode('ascii', errors='replace')
                                    # Remove whitespace from hex string
                                    hex_str = ''.join(hex_str.split())
                                    if len(hex_str) % 2 == 0:  # Valid hex has even length
                                        byte_str = bytes.fromhex(hex_str)
                                        value = byte_str.decode('utf-8', errors='replace')
                                        raw_metadata[label] = value
                                except Exception:
                                    pass
                                    
                        elif content[start:start+1] == b'/':
                            # Value is a name
                            end = start + 1
                            while end < len(content) and not content[end:end+1].isspace() and content[end:end+1] not in b'()<>/[]{}':
                                end += 1
                            
                            if end > start + 1:
                                try:
                                    value = content[start+1:end].decode('utf-8', errors='replace')
                                    raw_metadata[label] = value
                                except Exception:
                                    pass
            
            # Look for possible watermarks or document stamps that may contain owner info
            watermark_patterns = [
                (b'watermark', 'Watermark Text'),
                (b'confidential', 'Confidential Stamp'),
                (b'copyright', 'Copyright Text'),
                (b'property of', 'Property Statement')
            ]
            
            for pattern, label in watermark_patterns:
                pos = content.lower().find(pattern)
                if pos != -1:
                    # Try to extract some context around the pattern
                    start = max(0, pos - 50)
                    end = min(len(content), pos + len(pattern) + 50)
                    
                    try:
                        context = content[start:end].decode('utf-8', errors='replace')
                        raw_metadata[label] = context
                    except Exception:
                        pass
            
    except Exception as e:
        raw_metadata['Raw Extraction Error'] = str(e)
    
    return raw_metadata

def extract_document_structure_info(pdf_path):
    """
    Extract information about the document structure
    
    Args:
        pdf_path (str): Path to the PDF file
        
    Returns:
        dict: Dictionary containing document structure metadata
    """
    structure_info = {}
    
    try:
        # Use PyPDF2's lower-level capabilities to access PDF structures
        with open(pdf_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            
            # Access the PDF trailer dictionary if possible
            if hasattr(pdf_reader, '_trailer') and pdf_reader._trailer:
                trailer = pdf_reader._trailer
                
                # Extract Owner field if present
                if '/Owner' in trailer:
                    structure_info['Trailer Owner'] = str(trailer['/Owner'])
                
                # Check for any other interesting fields in the trailer
                for key in trailer:
                    if key not in ['/', '/Size', '/Root', '/Info', '/ID', '/Encrypt']:
                        structure_info[f'Trailer {key}'] = str(trailer[key])
            
            # Access document catalog dictionary for additional metadata
            if hasattr(pdf_reader, '_root'):
                catalog = pdf_reader._root
                
                # Look for metadata keys in the catalog
                metadata_keys = ['/Metadata', '/PieceInfo', '/OCProperties', '/Lang']
                for key in metadata_keys:
                    if key in catalog:
                        structure_info[f'Catalog {key}'] = 'Present'
                        
                # Extract document structure fields that might contain ownership information
                structure_keys = ['/MarkInfo', '/StructTreeRoot', '/ViewerPreferences']
                for key in structure_keys:
                    if key in catalog:
                        structure_info[f'Document Structure {key}'] = 'Present'
                
            # Check for document extensions
            if hasattr(pdf_reader, '_root') and '/Extensions' in pdf_reader._root:
                extensions = pdf_reader._root['/Extensions']
                structure_info['Document Extensions'] = str(extensions)
                
            # Try to extract document ID which can sometimes help identify the document
            if hasattr(pdf_reader, '_ID'):
                doc_id = pdf_reader._ID
                if doc_id and len(doc_id) > 0:
                    structure_info['Document ID'] = str(doc_id)
    
    except Exception as e:
        structure_info['Structure Extraction Error'] = str(e)
    
    return structure_info

def extract_first_page_text(pdf_reader):
    """
    Extract text from the first page which might contain header/footer with ownership info
    
    Args:
        pdf_reader: PyPDF2.PdfReader object
        
    Returns:
        dict: Dictionary containing extracted text that might contain ownership info
    """
    text_info = {}
    
    try:
        if len(pdf_reader.pages) > 0:
            first_page = pdf_reader.pages[0]
            text = first_page.extract_text()
            
            if text:
                # Look for ownership patterns in the text
                ownership_patterns = [
                    (r'(?i)owner:\s*([^\n]+)', 'Document Owner'),
                    (r'(?i)property\s+of\s+([^\n]+)', 'Property Of'),
                    (r'(?i)copyright\s+(?:©|\(c\))?\s*([^\n]+)', 'Copyright'),
                    (r'(?i)confidential(?:\s+to)?\s+([^\n]+)', 'Confidential To'),
                    (r'(?i)prepared\s+(?:for|by)\s+([^\n]+)', 'Prepared For/By'),
                    (r'(?i)company:?\s*([^\n]+)', 'Company'),
                    (r'(?i)department:?\s*([^\n]+)', 'Department')
                ]
                
                for pattern, label in ownership_patterns:
                    matches = re.search(pattern, text)
                    if matches and matches.group(1):
                        text_info[label] = matches.group(1).strip()
    
    except Exception as e:
        text_info['Text Extraction Error'] = str(e)
    
    return text_info

def extract_pdf_metadata(pdf_path):
    """
    Extract metadata from a PDF file
    
    Args:
        pdf_path (str): Path to the PDF file
        
    Returns:
        dict: Dictionary containing the PDF metadata
    """
    try:
        # Open the PDF file in binary read mode
        with open(pdf_path, 'rb') as file:
            # Create a PDF reader object
            pdf_reader = PyPDF2.PdfReader(file)
            
            # Get the document info dictionary
            metadata = pdf_reader.metadata
            
            if metadata is None:
                metadata = {}
            
            # Get encryption information
            encryption_info = {
                "Is Encrypted": pdf_reader.is_encrypted
            }
            
            # Add encryption method if the attribute exists
            if hasattr(pdf_reader, 'encryption_method'):
                encryption_info["Encryption Method"] = pdf_reader.encryption_method if pdf_reader.is_encrypted else "None"
            else:
                encryption_info["Encryption Method"] = "Unknown (information not available)"
            
            # Get permissions if the file is encrypted
            permissions = get_permissions_info(pdf_reader) if pdf_reader.is_encrypted else {
                "Permissions": "All Allowed (Document not encrypted)"
            }
            
            # Extract XMP metadata
            xmp_metadata = extract_xmp_metadata(pdf_reader)
            
            # Extract additional document info dictionary entries
            additional_info = extract_additional_info_dict_entries(pdf_reader)
            
            # Extract information from raw PDF content
            raw_metadata = extract_raw_metadata_from_file(pdf_path)
            
            # Extract document structure information
            structure_info = extract_document_structure_info(pdf_path)
            
            # Extract text from first page that might contain ownership info
            text_info = extract_first_page_text(pdf_reader)
            
            # Create a dictionary to store the cleaned metadata
            cleaned_metadata = {
                "Title": metadata.get('/Title', 'Not available'),
                "Author": metadata.get('/Author', 'Not available'),
                "Creator": metadata.get('/Creator', 'Not available'),
                "Producer": metadata.get('/Producer', 'Not available'),
                "Subject": metadata.get('/Subject', 'Not available'),
                "Keywords": metadata.get('/Keywords', 'Not available'),
                "Creation Date": parse_pdf_date(metadata.get('/CreationDate', 'Not available')),
                "Modification Date": parse_pdf_date(metadata.get('/ModDate', 'Not available')),
                "Number of Pages": len(pdf_reader.pages),
                **encryption_info,
                **permissions,
                **xmp_metadata,
                **additional_info,
                **raw_metadata,
                **structure_info,
                **text_info
            }
            
            return cleaned_metadata
            
    except FileNotFoundError:
        return {"error": f"File not found: {pdf_path}"}
    except Exception as e:
        return {"error": f"An error occurred: {str(e)}"}

def display_metadata(metadata):
    """
    Display the metadata in a formatted way
    
    Args:
        metadata (dict): Dictionary containing the PDF metadata
    """
    print("\n=== PDF Metadata ===")
    print("-" * 50)
    
    if "error" in metadata:
        print(f"Error: {metadata['error']}")
        return
    
    # Display basic metadata first
    basic_fields = ["Title", "Author", "Creator", "Producer", "Subject", "Keywords", 
                   "Creation Date", "Modification Date", "Number of Pages"]
    
    print("\n-- Basic Information --")
    for key in basic_fields:
        if key in metadata:
            print(f"{key}: {metadata[key]}")
    
    # Display security information
    print("\n-- Security Information --")
    if "Is Encrypted" in metadata:
        print(f"Is Encrypted: {metadata['Is Encrypted']}")
        print(f"Encryption Method: {metadata['Encryption Method']}")
    
    # Display permissions
    print("\n-- Document Permissions --")
    permission_fields = ["Print", "Modify", "Copy", "Annotate", "Forms", 
                        "Extract Content", "Assemble Document", "High Quality Print"]
    
    if "Permissions" in metadata:
        print(metadata["Permissions"])
    else:
        for perm in permission_fields:
            if perm in metadata:
                print(f"{perm}: {metadata[perm]}")
    
    # Look for ownership-related metadata first
    owner_fields = ["Document Owner", "Owner", "Raw Owner", "Property Of", "Company", 
                   "Copyright", "Raw Copyright", "Prepared For/By", "Confidential To",
                   "Department", "XMP xmpRights:Owner", "Trailer Owner"]
    
    print("\n-- Ownership Information --")
    owner_found = False
    for key in owner_fields:
        if key in metadata and metadata[key] != 'Not available':
            print(f"{key}: {metadata[key]}")
            owner_found = True
    
    if not owner_found:
        print("No ownership information found in the document")
    
    # Display XMP and additional metadata
    print("\n-- Additional Metadata --")
    
    # Sort the keys for better readability
    all_keys = sorted(metadata.keys())
    for key in all_keys:
        # Skip already displayed fields
        if (key in basic_fields or key in permission_fields or 
            key in ["Is Encrypted", "Encryption Method", "Permissions"] or
            key in owner_fields):
            continue
            
        # Skip fields with 'Not available' value for cleaner output
        if metadata[key] != 'Not available':
            print(f"{key}: {metadata[key]}")
    
    print("-" * 50)

def main():
    if len(sys.argv) != 2:
        print("Usage: python pdf_metadata.py <path_to_pdf>")
        sys.exit(1)
        
    pdf_path = sys.argv[1]
    metadata = extract_pdf_metadata(pdf_path)
    display_metadata(metadata)

if __name__ == "__main__":
    main() 