extern crate minisign;
use std::io::{Write, Read, Cursor};
use std::fs::{File};
use std::path::{Path};
use minisign::*;
use gldf_rs::{GldfProduct, FileBufGldf};
use gldf_rs::meta_information::{MetaInformation, Property};
use crate::helpers::*;
pub fn get_property(meta:&MetaInformation, name: &str) -> Option<Property> {
    for property in meta.property.iter() {
        if property.name == name {
            return Some(property.clone());
        }
    }
    None
}

pub fn check_ignore_path(path: &String) -> bool {
    if path.starts_with("meta-information.xml")  || path.starts_with("__MACOSX"){
        return true;
    }else{
        return false;
    }
}
pub fn get_gldf_buf_all(gldf_path: &Path) -> Result<FileBufGldf>{
    let mut gldf_file = File::open(gldf_path).unwrap();
    let mut gldf_file_buf = Vec::new();
    gldf_file.read_to_end(&mut gldf_file_buf)?;
    let file_buf = GldfProduct::load_gldf_from_buf_all(gldf_file_buf).unwrap();
    Ok(file_buf)
}

pub fn get_meta_information(gldf_file_buf:&FileBufGldf) -> Result<MetaInformation> {
    for a_file in gldf_file_buf.files.iter() {
        let path = a_file.clone().path.unwrap();
        if path.starts_with("meta-information.xml") {
            let content = a_file.clone().content.unwrap();
            let meta_xml_str  = String::from_utf8_lossy(&content);
            return Ok(MetaInformation::from_xml(&meta_xml_str.to_string()).unwrap());
        }
    }
    Err(PError::new(
        ErrorKind::Io,
        format!(
            "can't find meta-information.xml",
        ),
    ))
}
pub fn cmd_signgldf<P, Q, R>(
    pk: Option<PublicKey>,
    sk_path: P,
    _signature_path: Q,
    data_path: R,
    trusted_comment: Option<&str>,
    untrusted_comment: Option<&str>,
    passwordless: bool,
) -> Result<()>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
        R: AsRef<Path>,
{
    if !sk_path.as_ref().exists() {
        return Err(PError::new(
            ErrorKind::Io,
            format!(
                "can't find secret key file at {}, try using -s",
                sk_path.as_ref().display()
            ),
        ));
    }
    // read open zip file
    let mut meta_information = MetaInformation::default();
    let mut properties:Vec<Property> = Vec::new();
    let gldf_path = data_path.as_ref().to_str().unwrap();
    let gldf_filebufs = get_gldf_buf_all(data_path.as_ref())?;
    let sk = SecretKey::from_file(
        sk_path,
        if passwordless {
            Some(Default::default())
        } else {
            None
        },
    )?;
    let trusted_comment = if let Some(trusted_comment) = trusted_comment {
        trusted_comment.to_string()
    } else {
        format!(
            "timestamp:{}\tfile:{}\tprehashed",
            unix_timestamp(),
            data_path.as_ref().display()
        )
    };
    for a_file in gldf_filebufs.files.iter() {
        let path = a_file.clone().path.unwrap();
        if check_ignore_path(&path) {
            continue;
        }
        let content = a_file.clone().content.unwrap();
        let signature_box = sign(
            pk.as_ref(),
            &sk,
            Cursor::new(content),
            Some(trusted_comment.as_str()),
            untrusted_comment,
        )?;
        let xml_value = &signature_box.into_string();
        let property = Property {
            name: format!("gldf_rs_file_{}", path),
            property_text: xml_value.to_string(),
        };
        properties.push(property);
    }

    let pk_base64 = pk.unwrap().to_base64();
    let property = Property {
        name: "gldf_rs_file_public_key".to_string(),
        property_text: format!("{}", pk_base64),
    };
    properties.push(property);
    meta_information.property = properties;
    let zip_path = std::path::Path::new(gldf_path);
    let zip_file = std::fs::File::create(zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(zip_file);
    let _ = zip.start_file("meta-information.xml", zip::write::FileOptions::default());
    let _ = zip.write_all(meta_information.to_xml().unwrap().as_bytes())?;
    for a_file in gldf_filebufs.files.iter() {
        let path = a_file.clone().path.unwrap();
        let content = a_file.clone().content.unwrap();
        let _ = zip.start_file(path, zip::write::FileOptions::default());
        let _ = zip.write_all(&content);
    }
    let _ = zip.finish();
    // let mut zip = zip::ZipArchive::new(&mut data_reader);
    // OK so now write this into meta-information.xml
    Ok(())
}

pub fn cmd_verifygldf<P>(
    data_path: P,
    quiet: bool,
    output: bool,
    allow_legacy: bool,
) -> Result<()>
    where
        P: AsRef<Path>,

{
    let gldf_filebufs = get_gldf_buf_all(data_path.as_ref())?;
    let meta_information = get_meta_information(&gldf_filebufs)?;
    let public_key = get_property(&meta_information,"gldf_rs_file_public_key").unwrap();
    let pk = PublicKey::from_base64(&public_key.property_text).unwrap();

    for a_file in gldf_filebufs.files.iter() {
        let path = a_file.clone().path.unwrap();
        if check_ignore_path(&path){
            continue;
        }
        let content = a_file.clone().content.unwrap();
        let property  = get_property(&meta_information,  &format!("gldf_rs_file_{}", path));
        let property_value = match property {
            None => {
                return Err(PError::new(
                    ErrorKind::Io,
                    format!(
                        "can't find signature for {}",
                        path,
                    ),
                ));
            }
            _ => property.unwrap().property_text
        };
        let signature_box = SignatureBox::from_string(&property_value).map_err(|err| {
            PError::new(
                ErrorKind::Io,
                format!(
                    "could not read signature string {}: {}",
                    property_value.as_str(),
                    err
                ),
            )
        })?;
        let signature_box = verify(
            &pk,
            &signature_box,
            Cursor::new(content),
            quiet,
            output,
            allow_legacy
        );
        match signature_box {
            Ok(_) => {
                println!("OK");
            }
            Err(err) => {
                return Err(PError::new(
                    ErrorKind::Io,
                    format!(
                        "could not verify signature {}: {}",
                        property_value.as_str(),
                        err
                    ),
                ));
            }
        }
    }
    Ok(())
}

