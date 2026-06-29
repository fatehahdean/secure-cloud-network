// Secure Cloud Networking Architecture
// Author: Fatehah Burhannudin
// Azure-native IaC using Bicep
// Components: VNet, Subnets, NSG, RBAC, DDoS Protection

@description('Environment name')
param environmentName string = 'production'

@description('Azure region for deployment')
param location string = resourceGroup().location

@description('VNet address space')
param vnetAddressPrefix string = '10.0.0.0/16'

@description('Web subnet prefix')
param webSubnetPrefix string = '10.0.1.0/24'

@description('App subnet prefix')
param appSubnetPrefix string = '10.0.2.0/24'

@description('Data subnet prefix')
param dataSubnetPrefix string = '10.0.3.0/24'

@description('Management subnet prefix')
param mgmtSubnetPrefix string = '10.0.4.0/24'

// ============================================================
// NSG — Web Tier
// Allows inbound HTTP/HTTPS only
// ============================================================
resource nsgWeb 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: 'nsg-web-${environmentName}'
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-HTTPS-Inbound'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
          description: 'Allow HTTPS inbound from internet'
        }
      }
      {
        name: 'Allow-HTTP-Inbound'
        properties: {
          priority: 110
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
          description: 'Allow HTTP inbound - redirect to HTTPS'
        }
      }
      {
        name: 'Deny-All-Inbound'
        properties: {
          priority: 4096
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'Deny all other inbound traffic'
        }
      }
    ]
  }
}

// ============================================================
// NSG — App Tier
// Only allows traffic from web subnet
// ============================================================
resource nsgApp 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: 'nsg-app-${environmentName}'
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-From-Web-Subnet'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: webSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '8080'
          description: 'Allow traffic from web tier only'
        }
      }
      {
        name: 'Deny-All-Inbound'
        properties: {
          priority: 4096
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'Deny all other inbound traffic'
        }
      }
    ]
  }
}

// ============================================================
// NSG — Data Tier
// Only allows traffic from app subnet
// ============================================================
resource nsgData 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
  name: 'nsg-data-${environmentName}'
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-From-App-Subnet'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: appSubnetPrefix
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '1433'
          description: 'Allow SQL traffic from app tier only'
        }
      }
      {
        name: 'Deny-All-Inbound'
        properties: {
          priority: 4096
          protocol: '*'
          access: 'Deny'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'Deny all other inbound traffic'
        }
      }
    ]
  }
}

// ============================================================
// DDoS Protection Plan
// ============================================================
resource ddosProtectionPlan 'Microsoft.Network/ddosProtectionPlans@2023-04-01' = {
  name: 'ddos-plan-${environmentName}'
  location: location
  properties: {}
}

// ============================================================
// Virtual Network with 4 subnets
// ============================================================
resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
  name: 'vnet-secure-${environmentName}'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [vnetAddressPrefix]
    }
    enableDdosProtection: true
    ddosProtectionPlan: {
      id: ddosProtectionPlan.id
    }
    subnets: [
      {
        name: 'subnet-web'
        properties: {
          addressPrefix: webSubnetPrefix
          networkSecurityGroup: { id: nsgWeb.id }
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
      {
        name: 'subnet-app'
        properties: {
          addressPrefix: appSubnetPrefix
          networkSecurityGroup: { id: nsgApp.id }
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
      {
        name: 'subnet-data'
        properties: {
          addressPrefix: dataSubnetPrefix
          networkSecurityGroup: { id: nsgData.id }
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
      {
        name: 'subnet-mgmt'
        properties: {
          addressPrefix: mgmtSubnetPrefix
          privateEndpointNetworkPolicies: 'Enabled'
        }
      }
    ]
  }
}

// ============================================================
// Outputs
// ============================================================
output vnetId string = vnet.id
output vnetName string = vnet.name
output webSubnetId string = vnet.properties.subnets[0].id
output appSubnetId string = vnet.properties.subnets[1].id
output dataSubnetId string = vnet.properties.subnets[2].id
