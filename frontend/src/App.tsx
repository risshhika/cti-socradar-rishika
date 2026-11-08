import { lazy } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { AppShell } from './components/layout/AppShell'
const Overview = lazy(() => import('./pages/Overview'))
const Pipelines = lazy(() => import('./pages/Pipelines'))
const RunDetail = lazy(() => import('./pages/RunDetail'))
const Review = lazy(() => import('./pages/Review'))
const Settings = lazy(() => import('./pages/Settings'))
const PhishingOverview = lazy(() => import('./pages/phishing/PhishingOverview'))
const Campaigns = lazy(() => import('./pages/phishing/Campaigns'))
const CampaignDetail = lazy(() => import('./pages/phishing/CampaignDetail'))
const Kits = lazy(() => import('./pages/phishing/Kits'))
const KitDetail = lazy(() => import('./pages/phishing/KitDetail'))
const Samples = lazy(() => import('./pages/phishing/Samples'))
const SampleDetail = lazy(() => import('./pages/phishing/SampleDetail'))
const Detections = lazy(() => import('./pages/phishing/Detections'))
const LandscapeDashboard = lazy(() => import('./pages/landscape/LandscapeDashboard'))
const Victims = lazy(() => import('./pages/landscape/Victims'))
const Actors = lazy(() => import('./pages/landscape/Actors'))
const ActorDetail = lazy(() => import('./pages/landscape/ActorDetail'))
const IAB = lazy(() => import('./pages/landscape/IAB'))
const Briefings = lazy(() => import('./pages/landscape/Briefings'))
const BriefingDetail = lazy(() => import('./pages/landscape/BriefingDetail'))

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/" element={<Overview />} />
        <Route path="/phishing" element={<PhishingOverview />} />
        <Route path="/phishing/campaigns" element={<Campaigns />} />
        <Route path="/phishing/campaigns/:id" element={<CampaignDetail />} />
        <Route path="/phishing/kits" element={<Kits />} />
        <Route path="/phishing/kits/:id" element={<KitDetail />} />
        <Route path="/phishing/samples" element={<Samples />} />
        <Route path="/phishing/samples/:id" element={<SampleDetail />} />
        <Route path="/phishing/detections" element={<Detections />} />
        <Route path="/landscape" element={<LandscapeDashboard />} />
        <Route path="/landscape/victims" element={<Victims />} />
        <Route path="/landscape/actors" element={<Actors />} />
        <Route path="/landscape/actors/:slug" element={<ActorDetail />} />
        <Route path="/landscape/iab" element={<IAB />} />
        <Route path="/landscape/briefings" element={<Briefings />} />
        <Route path="/landscape/briefings/:id" element={<BriefingDetail />} />
        <Route path="/pipelines" element={<Pipelines />} />
        <Route path="/pipelines/runs/:id" element={<RunDetail />} />
        <Route path="/review" element={<Review />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
