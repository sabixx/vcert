<##################
.DESCRIPTION
    set-friendly-name sets the FriendlyName property on a certificate in the CAPI store
.PARAMETER thumbprint
    The thumbprint (SHA1 hash) of the certificate to update
.PARAMETER friendlyName
    The friendly name to set on the certificate
.PARAMETER storeName
    The name of the certificate store (e.g., "My")
.PARAMETER storeLocation
    The location of the certificate store (e.g., "LocalMachine" or "CurrentUser")
##################>
Set-StrictMode -Version Latest

function set-friendly-name {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string] $thumbprint,
        [Parameter(Mandatory)]
        [string] $friendlyName,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.storeName] $storeName,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.storeLocation] $storeLocation
    )

    # Open the certificate store with read/write access
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, $storeLocation)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)

    # Find certificate by thumbprint
    $cert = $store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint }

    if ($null -ne $cert) {
        $cert.FriendlyName = $friendlyName
        Write-Output "OK"
    } else {
        Write-Output "certificate not found: $thumbprint"
    }

    # Close the certificate store
    $store.Close()
}
