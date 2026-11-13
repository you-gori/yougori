import { useId } from "react"
import { ChevronDown, Network, Plus, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Field, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import { requestMethods, type AppConnection, type NetworkOptions } from "./network-options"

function ConnectionRows({ rows, onChange, kind, disabled }: {
  rows: AppConnection[]; onChange(rows: AppConnection[]): void; kind: "App" | "Connection"; disabled: boolean
}) {
  const id = useId()
  return <div className="creation-network-rows">
    {rows.map((row, index) => <div className="creation-network-row" key={index}>
      <Field><FieldLabel htmlFor={`${id}-${index}-name`}>{kind} name {index + 1}</FieldLabel>
        <Input id={`${id}-${index}-name`} className="creation-input" disabled={disabled} value={row.name} placeholder={kind === "App" ? "web" : "api"} onChange={event => onChange(rows.map((item, at) => at === index ? { ...item, name: event.target.value } : item))} />
      </Field>
      <Field><FieldLabel htmlFor={`${id}-${index}-port`}>{kind} port {index + 1}</FieldLabel>
        <Input id={`${id}-${index}-port`} className="creation-input" disabled={disabled} type="number" min={1} max={65535} value={row.port} onChange={event => onChange(rows.map((item, at) => at === index ? { ...item, port: event.target.value } : item))} />
      </Field>
      <Button type="button" variant="ghost" size="icon" disabled={disabled} aria-label={`Remove ${kind.toLowerCase()} ${index + 1}`} onClick={() => onChange(rows.filter((_, at) => at !== index))}><X aria-hidden="true" /></Button>
    </div>)}
    <Button type="button" variant="outline" size="sm" className="self-start" disabled={disabled || rows.length >= 8} onClick={() => onChange([...rows, { name: "", port: "8080" }])}><Plus aria-hidden="true" />Add {kind.toLowerCase()}</Button>
  </div>
}

export function NetworkOptionsForm({ value, onChange, disabled, gridHosting }: {
  value: NetworkOptions; onChange(value: NetworkOptions): void; disabled: boolean; gridHosting: boolean
}) {
  const id = useId()
  const change = (patch: Partial<NetworkOptions>) => onChange({ ...value, ...patch })
  const unrestrictedOutgoing = value.internet && value.outgoing
  return <details className="creation-vm-advanced" open>
    <summary><Network aria-hidden="true" /><span>Internet &amp; sharing</span><ChevronDown aria-hidden="true" /></summary>
    <div className="creation-vm-fields">
      <p className="creation-help">Choose what this sandbox can connect to. These options start off; turn on only what your project needs.</p>
      {gridHosting ? <p className="creation-help">Grid hosting also prepares its own grid service separately.</p> : null}
      <div className="creation-network-option">
        <div className="creation-network-toggle"><div>
          <label htmlFor={`${id}-internet`}>Full internet access</label>
          <p id={`${id}-internet-help`}>Choose separately what this sandbox can reach and who can connect to it.</p>
        </div><Switch id={`${id}-internet`} aria-describedby={`${id}-internet-help`} disabled={disabled} checked={value.internet} onCheckedChange={internet => change({ internet, ...(internet && value.outgoing ? { online: false } : {}) })} /></div>
        {value.internet ? <div className="creation-network-content">
          <div className="creation-network-option">
            <div className="creation-network-toggle"><div>
              <label htmlFor={`${id}-outgoing`}>Outgoing — allow all</label>
              <p id={`${id}-outgoing-help`}>Let apps use websites, APIs, and downloads on the public internet. Without GPU acceleration, they cannot reach your computer or your local network. Replies to these connections are allowed.</p>
            </div><Switch id={`${id}-outgoing`} aria-describedby={`${id}-outgoing-help`} disabled={disabled} checked={value.outgoing} onCheckedChange={outgoing => change({ outgoing, ...(outgoing ? { online: false } : {}) })} /></div>
          </div>
          <div className="creation-network-option">
            <div className="creation-network-toggle"><div>
              <label htmlFor={`${id}-incoming`}>Incoming — allow all</label>
              <p id={`${id}-incoming-help`}>Let other devices connect to every port in this VM.</p>
              <p id={`${id}-incoming-unavailable`}>Unavailable in this version. You can share individual apps below. Your computer’s network settings stay unchanged.</p>
            </div><Switch id={`${id}-incoming`} aria-describedby={`${id}-incoming-help ${id}-incoming-unavailable`} disabled checked={false} /></div>
          </div>
          <p className="creation-help">{unrestrictedOutgoing ? "Outgoing access is on. Unsolicited incoming connections stay blocked." : "General outgoing access is off. You can still allow specific online services below."} Access to your computer’s files is controlled separately.</p>
        </div> : null}
      </div>
      <div className="creation-network-option">
        <div className="creation-network-toggle"><div>
          <label htmlFor={`${id}-online`}>Connect to online services</label>
          <p id={`${id}-online-help`}>Allow specific requests to websites and APIs you choose.</p>
        </div><Switch id={`${id}-online`} aria-describedby={`${id}-online-help`} disabled={disabled || unrestrictedOutgoing} checked={value.online} onCheckedChange={online => change({ online })} /></div>
        {value.online ? <div className="creation-network-content">
          <p className="creation-help">Only the exact addresses and actions below are allowed. For general browsing and downloads, use Full internet access instead.</p>
          {!value.advanced ? <>
            {value.requests.map((request, index) => <div className="creation-network-request" key={index}>
              <Field><FieldLabel htmlFor={`${id}-url-${index}`}>Online address {index + 1}</FieldLabel>
                <Input id={`${id}-url-${index}`} className="creation-input" disabled={disabled} value={request.address} placeholder="https://api.example.com/v1/models" onChange={event => change({ requests: value.requests.map((item, at) => at === index ? { ...item, address: event.target.value } : item) })} />
              </Field>
              <div className="creation-network-row">
                <Field><FieldLabel htmlFor={`${id}-action-${index}`}>Allowed action {index + 1}</FieldLabel>
                  <select id={`${id}-action-${index}`} className="creation-vm-select" disabled={disabled} value={request.method} onChange={event => change({ requests: value.requests.map((item, at) => at === index ? { ...item, method: event.target.value } : item) })}>
                    {requestMethods.map(([method, label]) => <option key={method} value={method}>{label} ({method})</option>)}
                  </select>
                </Field>
                <Button type="button" variant="ghost" size="sm" disabled={disabled} onClick={() => change({ requests: value.requests.filter((_, at) => at !== index) })}>Remove address {index + 1}</Button>
              </div>
            </div>)}
            <p className="creation-help">“Read data” is the default. Choose “Send data” for an API that receives a prompt or form. Query values may vary; only the parameter names in your address are allowed. Don’t put passwords or API keys in the address.</p>
            <Button type="button" variant="outline" size="sm" className="self-start" disabled={disabled || value.requests.length >= 24} onClick={() => change({ requests: [...value.requests, { address: "", method: "GET" }] })}><Plus aria-hidden="true" />Add online address</Button>
          </> : null}
          <details className="creation-network-advanced"><summary>Advanced connection settings</summary>
            <div className="creation-network-toggle"><label htmlFor={`${id}-advanced`}>Enter connection rules manually</label><Switch id={`${id}-advanced`} checked={value.advanced} disabled={disabled} onCheckedChange={advanced => change({ advanced })} /></div>
            <p className="creation-help">For saved API credentials, custom limits, and other advanced settings. Manual rules replace the addresses above.</p>
            {value.advanced ? <Field><FieldLabel htmlFor={`${id}-rules`}>Connection rules (JSON)</FieldLabel><Textarea id={`${id}-rules`} className="creation-input creation-vm-routes" disabled={disabled} value={value.rules} onChange={event => change({ rules: event.target.value })} /></Field> : null}
          </details>
        </div> : null}
      </div>
      <div className="creation-network-option">
        <div className="creation-network-toggle"><div>
          <label htmlFor={`${id}-sharing`}>Open apps from this sandbox</label>
          <p id={`${id}-sharing-help`}>Prepare a website or API to open from Yougori after creation.</p>
        </div><Switch id={`${id}-sharing`} aria-describedby={`${id}-sharing-help`} disabled={disabled} checked={value.sharing} onCheckedChange={sharing => change({ sharing })} /></div>
        {value.sharing ? <div className="creation-network-content">
          <p className="creation-help">Default: web on port 3000, common for development websites. A port is the number your app listens on; match it to your app’s settings.</p>
          <div className="creation-network-presets"><Button type="button" size="sm" variant="outline" disabled={disabled} onClick={() => change({ apps: [{ name: "web", port: "3000" }] })}>Web app · 3000</Button><Button type="button" size="sm" variant="outline" disabled={disabled} onClick={() => change({ apps: [{ name: "api", port: "8080" }] })}>API · 8080</Button></div>
          <ConnectionRows rows={value.apps} kind="App" disabled={disabled} onChange={apps => change({ apps })} />
          <p className="creation-help">This prepares access; it does not install or start an app. After creation, choose Publish in the sandbox’s controls to open it. It is not made public on the internet automatically.</p>
        </div> : null}
      </div>
      <div className="creation-network-option">
        <div className="creation-network-toggle"><div>
          <label htmlFor={`${id}-connecting`}>Connect to other sandboxes</label>
          <p id={`${id}-connecting-help`}>Let this sandbox use an API or database running in another sandbox.</p>
        </div><Switch id={`${id}-connecting`} aria-describedby={`${id}-connecting-help`} disabled={disabled} checked={value.connecting} onCheckedChange={connecting => change({ connecting })} /></div>
        {value.connecting ? <div className="creation-network-content">
          <p className="creation-help">Default: api on port 8080. Your app can use this name once you connect it to a destination sandbox.</p>
          <div className="creation-network-presets"><Button type="button" size="sm" variant="outline" disabled={disabled} onClick={() => change({ connections: [{ name: "api", port: "8080" }] })}>API · 8080</Button><Button type="button" size="sm" variant="outline" disabled={disabled} onClick={() => change({ connections: [{ name: "db", port: "5432" }] })}>PostgreSQL · 5432</Button></div>
          <ConnectionRows rows={value.connections} kind="Connection" disabled={disabled} onChange={connections => change({ connections })} />
          <p className="creation-help">After creation, open Sandbox connections to choose the destination and approve it. No other sandbox is connected automatically.</p>
        </div> : null}
      </div>
    </div>
  </details>
}
