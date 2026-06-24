use crate::*;

impl BrainStore {
    pub fn create_vault_bootstrap(
        &mut self,
        output: &BootstrapOutput,
        grants: &[FolderKeyGrantMetadata],
    ) -> Result<(), StoreError> {
        if output.vault.folders.len() > MAX_BOOTSTRAP_FOLDERS {
            return Err(StoreError::BrokenInvariant {
                reason: format!("bootstrap folder count exceeds limit {MAX_BOOTSTRAP_FOLDERS}"),
            });
        }
        if grants.len() > MAX_BOOTSTRAP_GRANTS {
            return Err(StoreError::BrokenInvariant {
                reason: format!("bootstrap grant count exceeds limit {MAX_BOOTSTRAP_GRANTS}"),
            });
        }
        validate_bootstrap_output(output)?;
        validate_required_grants(&output.vault, &output.required_key_grants, grants)?;

        let tx = self.conn.transaction()?;
        insert_vault(&tx, &output.vault)?;
        insert_members_and_admins(&tx, &output.vault)?;
        for folder in &output.vault.folders {
            insert_folder(&tx, &output.vault.id, folder, false)?;
        }
        for grant in grants {
            insert_grant(&tx, &output.vault.id, grant)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Add an organization Vault Member.
    pub fn add_member(&mut self, vault_id: &VaultId, user_id: &UserId) -> Result<(), StoreError> {
        self.require_organization_vault(vault_id)?;
        self.conn.execute(
            "INSERT INTO vault_members (vault_id, user_id) VALUES (?1, ?2)",
            params![vault_id.as_str(), user_id.as_str()],
        )?;
        Ok(())
    }

    /// Add an organization Vault Admin. The user must already be a member.
    pub fn add_admin(&mut self, vault_id: &VaultId, user_id: &UserId) -> Result<(), StoreError> {
        self.require_organization_vault(vault_id)?;
        if !self.member_exists(vault_id, user_id)? {
            return Err(StoreError::BrokenInvariant {
                reason: "vault admin must already be a vault member".to_owned(),
            });
        }
        self.conn.execute(
            "INSERT INTO vault_admins (vault_id, user_id) VALUES (?1, ?2)",
            params![vault_id.as_str(), user_id.as_str()],
        )?;
        Ok(())
    }

    /// Remove an organization Vault Admin while preserving at least one admin.
    pub fn remove_admin(&mut self, vault_id: &VaultId, user_id: &UserId) -> Result<(), StoreError> {
        let vault = self.load_core_vault(vault_id)?;
        if vault.kind != VaultKind::Organization {
            return Err(StoreError::BrokenInvariant {
                reason: "member/admin mutation requires an organization vault".to_owned(),
            });
        }
        if !vault.admins.contains(user_id) {
            return Err(StoreError::BrokenInvariant {
                reason: "vault admin does not exist".to_owned(),
            });
        }
        if vault.admins.len() == 1 {
            return Err(StoreError::BrokenInvariant {
                reason: "organization vault must keep at least one admin".to_owned(),
            });
        }

        self.conn.execute(
            "DELETE FROM vault_admins WHERE vault_id = ?1 AND user_id = ?2",
            params![vault_id.as_str(), user_id.as_str()],
        )?;
        Ok(())
    }

    /// Remove an organization Vault Member after admin and restricted access cleanup.
    pub fn remove_member(
        &mut self,
        vault_id: &VaultId,
        user_id: &UserId,
    ) -> Result<(), StoreError> {
        let vault = self.load_core_vault(vault_id)?;
        if vault.kind != VaultKind::Organization {
            return Err(StoreError::BrokenInvariant {
                reason: "member/admin mutation requires an organization vault".to_owned(),
            });
        }
        if vault.admins.contains(user_id) {
            return Err(StoreError::BrokenInvariant {
                reason: "remove admin role before removing member".to_owned(),
            });
        }
        if !vault
            .members
            .iter()
            .any(|member| &member.user_id == user_id)
        {
            return Err(StoreError::BrokenInvariant {
                reason: "vault member does not exist".to_owned(),
            });
        }
        if self.member_has_restricted_access(vault_id, user_id)? {
            return Err(StoreError::BrokenInvariant {
                reason: "remove restricted folder access before removing member".to_owned(),
            });
        }

        self.conn.execute(
            "DELETE FROM vault_members WHERE vault_id = ?1 AND user_id = ?2",
            params![vault_id.as_str(), user_id.as_str()],
        )?;
        Ok(())
    }
}
