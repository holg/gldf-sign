extern crate minisign;
use zip::{ZipWriter};
use std::collections::HashMap;
use std::io::{Write, Read, Cursor};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use minisign::*;
use gldf_rs::{GldfProduct, FileBufGldf};
use gldf_rs::meta_information::{MetaInformation, Property};
use crate::helpers::*;
use regex::Regex;
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
    signature_path: Q,
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
        if path.starts_with("meta-information.xml") {
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

    let test = 1u8;
    let pk_base64 = pk.unwrap().to_base64();
    let property = Property {
        name: "gldf_rs_file_public_key".to_string(),
        property_text: format!("gldf_rs_public_key_{}", pk_base64),
    };
    properties.push(property);
    meta_information.property = properties;
    let zip_path = std::path::Path::new(gldf_path);
    let zip_file = std::fs::File::create(zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(zip_file);
    zip.start_file("meta-information.xml", zip::write::FileOptions::default());
    zip.write_all(meta_information.to_xml().unwrap().as_bytes())?;
    for a_file in gldf_filebufs.files.iter() {
        let path = a_file.clone().path.unwrap();
        let content = a_file.clone().content.unwrap();
        zip.start_file(path, zip::write::FileOptions::default());
        zip.write_all(&content);
    }
    zip.finish();
    // let mut zip = zip::ZipArchive::new(&mut data_reader);
    // OK so now write this into meta-information.xml
    Ok(())
}

pub fn cmd_verifygldf<P, Q>(
    pk: PublicKey,
    data_path: P,
    signature_path: Q,
    quiet: bool,
    output: bool,
    allow_legacy: bool,
) -> Result<()>
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
{
    let signature_box = SignatureBox::from_file(&signature_path).map_err(|err| {
        PError::new(
            ErrorKind::Io,
            format!(
                "could not read signature file {}: {}",
                signature_path.as_ref().display(),
                err
            ),
            )
    })?;
    let gldf_path = data_path.as_ref().to_str().unwrap();
    let gldf_filebufs = get_gldf_buf_all(data_path.as_ref())?;
    let mut meta_information = get_meta_information(&gldf_filebufs)?;
    for a_file in gldf_filebufs.files.iter() {
        let path = a_file.clone().path.unwrap();
        if path.starts_with("meta-information.xml") {
            continue;
        }
        let content = a_file.clone().content.unwrap();
        let signature_box = verify(
            &pk,
            &signature_box,
            Cursor::new(content),
            quiet,
            output,
            allow_legacy
        );
    }
    Ok(())
    // verify(
    //     &pk,
    //     &signature_box,
    //     data_reader,
    //     quiet,
    //     output,
    //     allow_legacy,
    // )
}

