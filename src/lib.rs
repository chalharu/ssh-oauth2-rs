use anyhow::Result;
use base64::{engine, Engine};
use pam::{
    constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_OFF, PAM_TEXT_INFO},
    items::User,
    module::{PamHandle, PamHooks},
    pam_try,
};
use qrcode::{render::unicode, QrCode};
use reqwest::{
    blocking::{Body, Client},
    header::{ACCEPT, CONTENT_TYPE},
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    time::Duration,
};

struct PamOauth2;
pam::pam_hooks!(PamOauth2);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeviceAuth {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: usize,
    interval: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Token {
    access_token: String,
    refresh_token: String,
    token_type: String,
    id_token: String,
    scope: String,
    session_state: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum JsonResult<T: Sized> {
    Ok(T),
    Err {
        error: String,
        error_description: Option<String>,
    },
}

impl PamHooks for PamOauth2 {
    fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        let args: Vec<_> = args.iter().map(|s| s.to_string_lossy()).collect();
        let args: HashMap<&str, &str> = args
            .iter()
            .map(|s| {
                let mut parts = s.splitn(2, '=');
                (parts.next().unwrap(), parts.next().unwrap_or(""))
            })
            .collect();

        let device_authorize_url: &str = match args.get("device_authorize_url") {
            Some(device_authorize_url) => device_authorize_url,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let token_url: &str = match args.get("token_url") {
            Some(token_url) => token_url,
            None => return PamResultCode::PAM_AUTH_ERR,
        };
        let client_id: &str = match args.get("client_id") {
            Some(client_id) => client_id,
            None => return PamResultCode::PAM_AUTH_ERR,
        };

        let conv = pam_try!(pamh.get_item::<pam::conv::Conv>()).unwrap();

        let post_data = format!("client_id={}&scope=openid%20profile", client_id);
        let result: DeviceAuth = match issue_post(device_authorize_url, post_data) {
            Ok(value) => value,
            Err(err) => {
                eprintln!("Device authorize error: {}", err);
                return PamResultCode::PAM_AUTH_ERR;
            }
        };

        eprintln!("auth: {} {}", result.user_code, result.device_code);

        let code = pam_try!(
            QrCode::new(&result.verification_uri_complete),
            PamResultCode::PAM_AUTH_ERR
        );
        let qr_code = code
            .render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Light)
            .light_color(unicode::Dense1x2::Dark)
            .build();
        pam_try!(conv.send(
            PAM_TEXT_INFO,
            &format!(
                "\n\nPlease login at {} or scan the QRCode below:\n\n{}",
                result.verification_uri_complete, qr_code
            )
        ));
        pam_try!(conv.send(PAM_PROMPT_ECHO_OFF, "Press Enter to continue:"));

        let post_data = format!(
            "device_code={}&grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id={}",
            result.device_code, client_id
        );

        let sleep = Duration::from_secs(result.interval.try_into().unwrap());
        for _ in 0..(result.expires_in / result.interval) {
            match issue_post(token_url, &post_data) as Result<JsonResult<Token>> {
                Ok(JsonResult::Ok(token)) => {
                    let decoded = pam_try!(
                        engine::general_purpose::STANDARD.decode(pam_try!(token
                            .id_token
                            .split('.')
                            .nth(1)
                            .ok_or(PamResultCode::PAM_AUTH_ERR))),
                        PamResultCode::PAM_AUTH_ERR
                    );
                    let id_token = pam_try!(
                        serde_json::from_slice::<'_, Value>(&decoded),
                        PamResultCode::PAM_AUTH_ERR
                    );

                    let preferred_username = pam_try!(pam_try!(id_token
                        .get("preferred_username")
                        .ok_or(PamResultCode::PAM_AUTH_ERR))
                    .as_str()
                    .ok_or(PamResultCode::PAM_AUTH_ERR));

                    if let Some(user) = pam_try!(pamh.get_item::<User>()) {
                        let user = pam_try!(user.to_str(), PamResultCode::PAM_AUTH_ERR);
                        if preferred_username != user {
                            eprintln!(
                                "username unmatch: [preferred_username]{}, [pam_user]{}",
                                preferred_username, user
                            );
                            return PamResultCode::PAM_AUTH_ERR;
                        }
                    } else {
                        let preferred_username_c = pam_try!(
                            CString::new(preferred_username),
                            PamResultCode::PAM_AUTH_ERR
                        );
                        let user = User(preferred_username_c.as_c_str());
                        pam_try!(pamh.set_item_str(user));
                    }

                    eprintln!("OAuth2 Device flow successed");
                    return PamResultCode::PAM_SUCCESS;
                }
                Ok(JsonResult::Err {
                    error,
                    error_description,
                }) => {
                    eprintln!(
                        "{}",
                        error_description
                            .map_or_else(|| error.to_string(), |d| format!("{}: {}", error, d))
                    );
                }
                Err(e) => {
                    eprintln!("{}", e);
                }
            }
            std::thread::sleep(sleep);
        }

        PamResultCode::PAM_AUTH_ERR
    }

    fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_SUCCESS
    }
}

fn issue_post<S: Into<String>, T: DeserializeOwned>(url: &str, body: S) -> Result<T> {
    let client = Client::builder().timeout(Duration::from_secs(15)).build()?;
    let body_data = Body::from(body.into());
    let response = client
        .post(url)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(ACCEPT, "application/json")
        .body(body_data)
        .send()?;
    let text = response.text()?;
    Ok(serde_json::from_str(text.as_str())?)
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {}
// }
