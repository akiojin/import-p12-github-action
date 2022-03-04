import * as exec from '@actions/exec'

export class Security
{
	static ImportCertificateFromFile(keychain: string, certificate: string, passphrase: string): Promise<number>
	{
		const args = [
			'import', certificate,
			'-k', keychain,
			'-P', passphrase,
			'-f', 'pkcs12',
			'-A',
			'-T', '/usr/bin/codesign',
			'-T', '/usr/bin/security'
		]

		return exec.exec('security', args)
	}

	static LockKeychain(keychain?: string): Promise<number>
	{
		if (keychain == null) {
			return exec.exec('security', ['lock-keychain'])
		} else {
			return exec.exec('security', ['lock-keychain', keychain])
		}
	}

	static LockKeychainAll(): Promise<number>
	{
		return exec.exec('security', ['lock-keychain', '-a'])
	}

	static UnlockKeychain(keychain: string, password: string): Promise<number>
	static UnlockKeychain(password: string): Promise<number>
	static UnlockKeychain(keychain?: string, password?: string): Promise<number>
	{
		if (password == null) {
			throw new Error('Password required.')
		}

		if (keychain != null) {
			return exec.exec('security', ['unlock-keychain', '-p', password, keychain])
		} else {
			return exec.exec('security', ['unlock-keychain', '-p', password])
		}
	}

	static async CreateKeychain(keychain: string, password: string): Promise<number>
	{
		if (password === '') {
			throw new Error('Password required.')
		}

		await exec.exec('security', ['create-keychain', '-p', password, keychain])
		// Default settings
		return exec.exec('security', ['set-keychain-settings', '-lut', '21600', keychain])
	}

	static DeleteKeychain(keychain: string): Promise<number>
	{
		return exec.exec('security', ['delete-keychain', keychain])
	}

	static SetKeychain(name: string, keychain: string): Promise<number>
	{
		return exec.exec('security', [name, '-d', 'user', '-s', keychain])
	}

	static SetDefaultKeychain(keychain: string): Promise<number>
	{
		return this.SetKeychain('default-keychain', keychain)
	}

	static ShowDefaultKeychain(): Promise<number>
	{
		return exec.exec('security', ['default-keychain'])
	}

	static SetLoginKeychain(keychain: string): Promise<number>
	{
		return this.SetKeychain('login-keychain', keychain)
	}

	static ShowLoginKeychain(): Promise<number>
	{
		return exec.exec('security', ['login-keychain'])
	}

	static ShowListKeychains(): Promise<number>
	{
		return exec.exec('security', ['list-keychains', '-d', 'user'])
	}

	static SetListKeychains(keychain: string): Promise<number>
	{
		return exec.exec('security', ['list-keychains', '-d', 'user', '-s', keychain])
	}

	static FindGenericPassword(service: string)
	{
		return exec.exec('security', ['find-generic-password', '-s', `"${service}"`])
	}
}
