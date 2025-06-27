'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/components/auth-provider'
import { identityClient, getAuthPath } from '@/lib/api-client'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { 
  CreditCard, 
  DollarSign, 
  Calendar, 
  CheckCircle, 
  XCircle,
  Crown,
  Zap,
  Users,
  AlertCircle
} from 'lucide-react'
import { useToast } from '@/hooks/use-toast'
import { Subscription, Team } from '@/types'

interface BillingData {
  subscription?: Subscription
  team?: Team
  usage?: {
    api_calls: number
    storage_gb: number
    team_members: number
  }
  limits?: {
    api_calls: number
    storage_gb: number
    team_members: number
  }
}

const plans = {
  free: {
    name: 'Free',
    price: '$0',
    period: 'forever',
    features: [
      'Up to 3 team members',
      '1,000 API calls per month',
      '1 GB storage',
      'Basic security tools',
      'Community support'
    ],
    icon: CheckCircle,
    color: 'text-gray-500'
  },
  pro: {
    name: 'Pro',
    price: '$29',
    period: 'per month',
    features: [
      'Up to 10 team members',
      '50,000 API calls per month',
      '10 GB storage',
      'All security tools',
      'Priority support',
      'Advanced analytics'
    ],
    icon: Zap,
    color: 'text-blue-500'
  },
  business: {
    name: 'Business',
    price: '$99',
    period: 'per month',
    features: [
      'Unlimited team members',
      'Unlimited API calls',
      '100 GB storage',
      'All security tools',
      'Priority support',
      'Advanced analytics',
      'Custom integrations',
      'Dedicated account manager'
    ],
    icon: Crown,
    color: 'text-purple-500'
  }
}

export default function BillingPage() {
  const { user } = useAuth()
  const { toast } = useToast()
  const [billingData, setBillingData] = useState<BillingData | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isUpgrading, setIsUpgrading] = useState(false)

  useEffect(() => {
    if (user) {
      fetchBillingData()
    }
  }, [user])

  const fetchBillingData = async () => {
    try {
      setIsLoading(true)
      
      // Try to get real billing data first
      try {
        const billingResponse = await identityClient.get('/api/v1/billing/subscription')
        setBillingData(billingResponse)
        return
      } catch (error) {
        console.log('Billing endpoint not available, using mock data')
      }
      
      // Fallback to mock data with user data
      const userData = await identityClient.get(getAuthPath('/api/v1/auth/me'))
      
      setBillingData({
        subscription: userData.team_memberships?.[0]?.team?.subscription || {
          plan_id: 'free',
          status: 'active'
        },
        team: userData.team_memberships?.[0]?.team,
        usage: {
          api_calls: 450,
          storage_gb: 0.5,
          team_members: userData.team_memberships?.length || 1
        },
        limits: {
          api_calls: 1000,
          storage_gb: 1,
          team_members: 3
        }
      })
    } catch (error: any) {
      console.error('Failed to fetch billing data:', error)
      toast({
        title: "Error",
        description: "Failed to load billing information",
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleUpgrade = async (planId: string) => {
    setIsUpgrading(true)
    try {
      // Try to create a Stripe checkout session
      const checkoutResponse = await identityClient.post('/api/v1/billing/create-checkout-session', {
        plan_id: planId,
        success_url: `${window.location.origin}/settings/billing?success=true`,
        cancel_url: `${window.location.origin}/settings/billing?canceled=true`
      })
      
      // Redirect to Stripe checkout
      if (checkoutResponse.checkout_url) {
        window.location.href = checkoutResponse.checkout_url
      } else {
        throw new Error('No checkout URL returned')
      }
    } catch (error: any) {
      console.log('Stripe checkout not available:', error)
      
      // Fallback message for demo
      toast({
        title: "Coming Soon",
        description: "Subscription management will be available soon. This is a demo implementation.",
      })
    } finally {
      setIsUpgrading(false)
    }
  }

  const handleManageBilling = async () => {
    try {
      // Try to create a customer portal session
      const portalResponse = await identityClient.post('/api/v1/billing/create-portal-session')
      
      if (portalResponse.portal_url) {
        window.location.href = portalResponse.portal_url
      } else {
        throw new Error('No portal URL returned')
      }
    } catch (error: any) {
      console.log('Customer portal not available:', error)
      
      toast({
        title: "Coming Soon",
        description: "Billing management portal will be available soon.",
      })
    }
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString()
  }

  const getUsagePercentage = (used: number, limit: number) => {
    return Math.min((used / limit) * 100, 100)
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertCircle className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground">Please log in to view billing information</p>
        </div>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="text-muted-foreground">Loading billing information...</div>
        </div>
      </div>
    )
  }

  const currentPlan = billingData?.subscription?.plan_id || 'free'
  const currentPlanData = plans[currentPlan as keyof typeof plans]

  return (
    <div className="max-w-6xl">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-foreground">Billing & Subscription</h1>
        <p className="text-muted-foreground mt-2">
          Manage your subscription and view usage
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Current Plan */}
        <Card className="p-6">
          <div className="flex items-center gap-3 mb-4">
            <div className={`w-8 h-8 ${currentPlanData.color}`}>
              <currentPlanData.icon className="w-8 h-8" />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-foreground">Current Plan</h3>
              <Badge variant={billingData?.subscription?.status === 'active' ? "default" : "secondary"}>
                {billingData?.subscription?.status || 'active'}
              </Badge>
            </div>
          </div>
          
          <div className="space-y-2">
            <div className="text-2xl font-bold">{currentPlanData.name}</div>
            <div className="text-muted-foreground">
              {currentPlanData.price} {currentPlanData.period}
            </div>
            {billingData?.subscription?.current_period_end && (
              <div className="text-sm text-muted-foreground flex items-center gap-2">
                <Calendar className="w-4 h-4" />
                Renews {formatDate(billingData.subscription.current_period_end)}
              </div>
            )}
          </div>
        </Card>

        {/* Usage Overview */}
        <Card className="p-6">
          <div className="flex items-center gap-3 mb-4">
            <DollarSign className="w-8 h-8 text-green-500" />
            <h3 className="text-lg font-semibold text-foreground">Usage</h3>
          </div>
          
          <div className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>API Calls</span>
                <span>{billingData?.usage?.api_calls || 0} / {billingData?.limits?.api_calls || 0}</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div 
                  className="bg-primary h-2 rounded-full" 
                  style={{ 
                    width: `${getUsagePercentage(
                      billingData?.usage?.api_calls || 0, 
                      billingData?.limits?.api_calls || 1
                    )}%` 
                  }}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Storage</span>
                <span>{billingData?.usage?.storage_gb || 0} GB / {billingData?.limits?.storage_gb || 0} GB</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div 
                  className="bg-primary h-2 rounded-full" 
                  style={{ 
                    width: `${getUsagePercentage(
                      billingData?.usage?.storage_gb || 0, 
                      billingData?.limits?.storage_gb || 1
                    )}%` 
                  }}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-sm mb-1">
                <span>Team Members</span>
                <span>{billingData?.usage?.team_members || 0} / {billingData?.limits?.team_members || 0}</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2">
                <div 
                  className="bg-primary h-2 rounded-full" 
                  style={{ 
                    width: `${getUsagePercentage(
                      billingData?.usage?.team_members || 0, 
                      billingData?.limits?.team_members || 1
                    )}%` 
                  }}
                ></div>
              </div>
            </div>
          </div>
        </Card>

        {/* Payment Method */}
        <Card className="p-6">
          <div className="flex items-center gap-3 mb-4">
            <CreditCard className="w-8 h-8 text-blue-500" />
            <h3 className="text-lg font-semibold text-foreground">Payment Method</h3>
          </div>
          
          <div className="space-y-2">
            {currentPlan === 'free' ? (
              <div className="text-muted-foreground">No payment method required for free plan</div>
            ) : (
              <div>
                <div className="text-sm text-muted-foreground">Card ending in ****</div>
                <div className="text-sm text-muted-foreground">Expires 12/25</div>
              </div>
            )}
            
            {currentPlan !== 'free' && (
              <div className="space-y-2">
                <Button variant="outline" size="sm" onClick={handleManageBilling}>
                  Manage Billing
                </Button>
                <Button variant="outline" size="sm" className="ml-2">
                  Update Payment Method
                </Button>
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Available Plans */}
      <div className="mb-8">
        <h2 className="text-2xl font-bold text-foreground mb-6">Available Plans</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {Object.entries(plans).map(([planId, plan]) => {
            const Icon = plan.icon
            const isCurrent = planId === currentPlan
            
            return (
              <Card key={planId} className={`p-6 relative ${isCurrent ? 'ring-2 ring-primary' : ''}`}>
                {isCurrent && (
                  <Badge className="absolute -top-2 left-1/2 transform -translate-x-1/2">
                    Current Plan
                  </Badge>
                )}
                
                <div className="text-center mb-6">
                  <Icon className={`w-12 h-12 mx-auto mb-4 ${plan.color}`} />
                  <h3 className="text-xl font-bold text-foreground">{plan.name}</h3>
                  <div className="text-3xl font-bold text-foreground mt-2">{plan.price}</div>
                  <div className="text-muted-foreground">{plan.period}</div>
                </div>

                <ul className="space-y-3 mb-6">
                  {plan.features.map((feature, index) => (
                    <li key={index} className="flex items-center gap-2 text-sm">
                      <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
                      <span>{feature}</span>
                    </li>
                  ))}
                </ul>

                <Button 
                  className="w-full" 
                  variant={isCurrent ? "outline" : "default"}
                  disabled={isCurrent || isUpgrading}
                  onClick={() => handleUpgrade(planId)}
                >
                  {isCurrent ? 'Current Plan' : `Upgrade to ${plan.name}`}
                </Button>
              </Card>
            )
          })}
        </div>
      </div>

      {/* Billing History */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold text-foreground mb-4">Billing History</h3>
        
        <div className="text-center py-8">
          <div className="text-muted-foreground">No billing history available</div>
          <div className="text-sm text-muted-foreground mt-1">
            {currentPlan === 'free' ? 'Upgrade to a paid plan to see billing history' : 'Invoices will appear here once available'}
          </div>
        </div>
      </Card>
    </div>
  )
}
