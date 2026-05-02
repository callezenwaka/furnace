<template>
  <div class="landing">
    <!-- Hero -->
    <section class="hero">
      <div class="container">
        <h1>Build Auth Flows Locally</h1>
        <p class="subtitle">
          Develop, test, and iterate authentication flows before integrating
          production SSO providers.
        </p>

        <div class="actions">
          <button @click="getStarted">Get Started</button>
          <button class="secondary" @click="viewDocs">View Docs</button>
        </div>
      </div>
    </section>

    <!-- Features -->
    <section class="features">
      <div class="container">
        <h2>Designed for Authentication Development</h2>

        <div class="feature-grid">
          <div v-for="feature in features" :key="feature.title" class="feature">
            <h3>{{ feature.title }}</h3>
            <p>{{ feature.description }}</p>
          </div>
        </div>
      </div>
    </section>

    <!-- Workflow -->
    <section class="workflow">
      <div class="container">
        <h2>Simple Development Workflow</h2>

        <ol class="steps">
          <li v-for="step in steps" :key="step">
            {{ step }}
          </li>
        </ol>
      </div>
    </section>

    <!-- CTA -->
    <section class="cta">
      <div class="container">
        <h2>Stop Fighting Auth During Development</h2>
        <p>
          Prototype authentication flows locally and switch to real SSO when
          you're ready.
        </p>

        <button @click="getStarted">Start Building</button>
      </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
      <div class="container">
        <p>© {{ year }} Auth Dev Platform</p>
      </div>
    </footer>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue"

interface Feature {
  title: string
  description: string
}

const year = new Date().getFullYear()

const features = ref<Feature[]>([
  {
    title: "Local Identity Provider",
    description:
      "Simulate authentication providers locally without relying on external services."
  },
  {
    title: "Test Any Auth Flow",
    description:
      "Prototype OAuth, SSO, token refresh, and edge cases before production."
  },
  {
    title: "Fast Iteration",
    description:
      "Develop and debug authentication without waiting on external providers."
  },
  {
    title: "Provider Agnostic",
    description:
      "Switch to Auth0, Okta, Azure AD, or any SSO provider once flows are stable."
  }
])

const steps = ref<string[]>([
  "Define authentication flows locally",
  "Test login, logout, refresh, and edge cases",
  "Integrate your frontend or API",
  "Swap the local provider for a real SSO provider"
])

function getStarted() {
  window.location.href = "/docs"
}

function viewDocs() {
  window.location.href = "/docs"
}
</script>

<style scoped>
.landing {
  font-family: system-ui, -apple-system, sans-serif;
  color: #111;
}

.container {
  max-width: 1100px;
  margin: auto;
  padding: 3rem 1.5rem;
}

.hero {
  text-align: center;
  padding: 5rem 0;
}

.hero h1 {
  font-size: 3rem;
  margin-bottom: 1rem;
}

.subtitle {
  font-size: 1.2rem;
  color: #555;
}

.actions {
  margin-top: 2rem;
}

button {
  padding: 0.8rem 1.4rem;
  margin: 0.4rem;
  border: none;
  border-radius: 6px;
  background: #2563eb;
  color: white;
  font-weight: 600;
  cursor: pointer;
}

button.secondary {
  background: #e5e7eb;
  color: #111;
}

.features {
  background: #f9fafb;
}

.feature-grid {
  margin-top: 2rem;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 1.5rem;
}

.feature {
  padding: 1.5rem;
  border-radius: 8px;
  background: white;
  border: 1px solid #eee;
}

.workflow {
  text-align: center;
}

.steps {
  margin-top: 2rem;
  text-align: left;
  display: inline-block;
}

.steps li {
  margin-bottom: 0.8rem;
}

.cta {
  text-align: center;
  background: #111827;
  color: white;
}

.cta button {
  margin-top: 1.5rem;
  background: #3b82f6;
}

.footer {
  text-align: center;
  font-size: 0.9rem;
  color: #666;
}
</style>